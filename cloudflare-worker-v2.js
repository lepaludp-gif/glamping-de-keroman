export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // === 1. Proxy iCal Booking (existant) ===
    if (url.pathname === '/' || url.pathname === '') {
      const target = url.searchParams.get('url');
      if (!target) return new Response('Paramètre "url" manquant', { status: 400 });
      if (!target.startsWith('https://ical.booking.com/')) {
        return new Response('Seules les URLs ical.booking.com sont autorisées.', { status: 403 });
      }
      try {
        const res = await fetch(target);
        const text = await res.text();
        return new Response(text, {
          status: res.status,
          headers: {
            'Content-Type': 'text/calendar; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=3600'
          }
        });
      } catch (e) {
        return new Response('Erreur: ' + e.message, { status: 502 });
      }
    }

    // === 2. Stripe Checkout ===
    if (url.pathname === '/stripe-checkout') {

      // CORS preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
          }
        });
      }

      if (request.method !== 'POST') {
        return new Response('Méthode non autorisée', { status: 405 });
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return new Response('JSON invalide', { status: 400 });
      }

      const { montant, tente, arrivee, depart, nuits } = body;

      // Validation
      if (!montant || montant < 65 || montant > 5000) {
        return new Response('Montant invalide', { status: 400 });
      }
      if (!tente || !arrivee || !depart) {
        return new Response('Paramètres manquants', { status: 400 });
      }

      // Créer la session Stripe Checkout
      const stripeRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          'payment_method_types[]': 'card',
          'line_items[0][price_data][currency]': 'eur',
          'line_items[0][price_data][product_data][name]': `Glamping de Keroman — Tente ${tente}`,
          'line_items[0][price_data][product_data][description]': `Séjour du ${arrivee} au ${depart} (${nuits} nuit${nuits > 1 ? 's' : ''})`,
          'line_items[0][price_data][unit_amount]': String(Math.round(montant * 100)),
          'line_items[0][quantity]': '1',
          'mode': 'payment',
          'success_url': 'https://glamping-keroman.fr/merci.html',
          'cancel_url': `https://glamping-keroman.fr/tente-${tente.toLowerCase()}.html`,
          'locale': 'fr',
          // Métadonnées : permettent de retrouver facilement les détails de la
          // réservation dans le webhook, sans avoir à reparser la description.
          'metadata[tente]': tente,
          'metadata[arrivee]': arrivee,
          'metadata[depart]': depart,
          'metadata[nuits]': String(nuits),
          'metadata[montant]': String(montant),
        }).toString()
      });

      const stripeData = await stripeRes.json();

      if (!stripeRes.ok) {
        console.error('Stripe error:', stripeData);
        return new Response(JSON.stringify({ error: stripeData.error?.message || 'Erreur Stripe' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
      }

      return new Response(JSON.stringify({ url: stripeData.url }), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // === 3. Webhook Stripe : envoi automatique des emails de confirmation ===
    if (url.pathname === '/stripe-webhook') {

      if (request.method !== 'POST') {
        return new Response('Méthode non autorisée', { status: 405 });
      }

      const signature = request.headers.get('stripe-signature');
      const payload = await request.text();

      if (!signature) {
        return new Response('Signature manquante', { status: 400 });
      }

      // Vérification de la signature Stripe (sécurité anti-usurpation)
      const isValid = await verifyStripeSignature(payload, signature, env.STRIPE_WEBHOOK_SECRET);
      if (!isValid) {
        return new Response('Signature invalide', { status: 400 });
      }

      let event;
      try {
        event = JSON.parse(payload);
      } catch {
        return new Response('JSON invalide', { status: 400 });
      }

      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        const email = session.customer_details?.email || session.customer_email || null;
        const meta = session.metadata || {};
        const tente = meta.tente || 'N/A';
        const arrivee = meta.arrivee || 'N/A';
        const depart = meta.depart || 'N/A';
        const nuits = meta.nuits || '?';
        const montant = ((session.amount_total || 0) / 100).toFixed(2);

        // Envoi des emails en parallèle ; on n'échoue jamais le webhook
        // pour Stripe même si l'envoi d'email plante (Stripe réessaie sinon
        // indéfiniment un webhook qui répond en erreur).
        try {
          await Promise.all([
            sendClientEmail(env, email, tente, arrivee, depart, nuits, montant),
            sendOwnerEmail(env, email, tente, arrivee, depart, nuits, montant),
          ]);
        } catch (e) {
          console.error('Erreur envoi email:', e.message);
        }
      }

      return new Response(JSON.stringify({ received: true }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Route inconnue', { status: 404 });
  }
};

// === Vérification de la signature du webhook Stripe ===
async function verifyStripeSignature(payload, signatureHeader, secret) {
  try {
    const parts = Object.fromEntries(
      signatureHeader.split(',').map(p => p.split('='))
    );
    const timestamp = parts.t;
    const receivedSig = parts.v1;
    if (!timestamp || !receivedSig) return false;

    const signedPayload = `${timestamp}.${payload}`;

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signedPayload));
    const expectedSig = Array.from(new Uint8Array(sigBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    // Tolérance de 5 minutes sur l'horodatage (protection anti-rejeu)
    const age = Math.abs(Date.now() / 1000 - Number(timestamp));
    if (age > 300) return false;

    return expectedSig === receivedSig;
  } catch {
    return false;
  }
}

// === Email envoyé à la cliente ===
async function sendClientEmail(env, toEmail, tente, arrivee, depart, nuits, montant) {
  if (!toEmail) return;
  await sendEmail(env, {
    to: toEmail,
    subject: 'Confirmation de votre réservation – Glamping de Keroman',
    html: `
      <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
        <h2 style="color:#065f46">Réservation confirmée !</h2>
        <p>Bonjour,</p>
        <p>Merci pour votre réservation au Glamping de Keroman. Voici le récapitulatif de votre séjour :</p>
        <table style="width:100%;border-collapse:collapse;margin:20px 0">
          <tr><td style="padding:8px 0;color:#57534e">Tente</td><td style="padding:8px 0;font-weight:bold">${tente}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Arrivée</td><td style="padding:8px 0;font-weight:bold">${arrivee}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Départ</td><td style="padding:8px 0;font-weight:bold">${depart}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Nuits</td><td style="padding:8px 0;font-weight:bold">${nuits}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Montant réglé</td><td style="padding:8px 0;font-weight:bold">${montant} €</td></tr>
        </table>
        <p>Nous reviendrons vers vous prochainement avec les informations pratiques pour votre arrivée.</p>
        <p>À très bientôt,<br>L'équipe du Glamping de Keroman</p>
        <hr style="border:none;border-top:1px solid #e7e5e4;margin:24px 0">
        <p style="font-size:13px;color:#a8a29e">Kéroman, 56650 Inzinzac-Lochrist · 06 85 50 24 42</p>
      </div>
    `
  });
}

// === Email envoyé au propriétaire ===
async function sendOwnerEmail(env, clientEmail, tente, arrivee, depart, nuits, montant) {
  await sendEmail(env, {
    to: 'contact@glamping-keroman.fr',
    subject: `Nouvelle réservation — Tente ${tente} (${arrivee})`,
    html: `
      <div style="font-family:sans-serif;max-width:560px;margin:0 auto">
        <h2>Nouvelle réservation reçue</h2>
        <table style="width:100%;border-collapse:collapse;margin:20px 0">
          <tr><td style="padding:8px 0;color:#57534e">Client</td><td style="padding:8px 0;font-weight:bold">${clientEmail || 'Email non fourni'}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Tente</td><td style="padding:8px 0;font-weight:bold">${tente}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Arrivée</td><td style="padding:8px 0;font-weight:bold">${arrivee}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Départ</td><td style="padding:8px 0;font-weight:bold">${depart}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Nuits</td><td style="padding:8px 0;font-weight:bold">${nuits}</td></tr>
          <tr><td style="padding:8px 0;color:#57534e">Montant réglé</td><td style="padding:8px 0;font-weight:bold">${montant} €</td></tr>
        </table>
        <p style="color:#d97706">⚠ Pensez à bloquer ces dates sur le calendrier Google de la tente correspondante.</p>
      </div>
    `
  });
}

// === Fonction générique d'envoi via Resend ===
async function sendEmail(env, { to, subject, html }) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'Glamping de Keroman <reservations@glamping-keroman.fr>',
      to: [to],
      subject,
      html,
    })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Resend error (${res.status}): ${err}`);
  }
}

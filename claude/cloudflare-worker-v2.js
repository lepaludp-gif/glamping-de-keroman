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

    return new Response('Route inconnue', { status: 404 });
  }
};

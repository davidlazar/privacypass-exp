// privacypass.js adds "Login with Privacy Pass" to a page. It gets a token
// from the user's Privacy Pass wallet and redeems it at the page's own
// server, which can then treat the visitor as logged in without learning who
// they are.
//
// Load it from the wallet's host, and call privacyPassLogin from a click
// handler (the wallet opens in a popup, which browsers allow only then):
//
//	<script src="https://wallet.example/privacypass.js"></script>
//	<button onclick="privacyPassLogin('/login').then(...)">Login with Privacy Pass</button>
//
// Send the page with "Referrer-Policy: no-referrer". Otherwise the browser
// tells the wallet's host which page the user is on, both when it loads this
// script and when it opens the wallet.
//
// privacyPassLogin(url) POSTs to url, which should answer 401 with a
// "WWW-Authenticate: PrivateToken challenge=..." header (RFC 9577). It asks
// the wallet for a token for that challenge, POSTs to url again with
// "Authorization: PrivateToken token=...", and returns the response.
//
// The page and the wallet talk by postMessage. The wallet posts
// {type: 'privacypass-ready'} when it has loaded (and again if it reloads),
// and gets back {type: 'privacypass-request', challenge}. If it holds tokens
// for that kind of challenge, it asks the user (who can first log in or get
// more tokens if it's out), then answers with
// {type: 'privacypass-token', token} or {type: 'privacypass-error', error}.
// Otherwise it answers with the error right away. The challenge and the token
// are base64url with padding, as in the headers.
(() => {
    // The wallet is served next to this script.
    const walletURL = new URL('wallet', document.currentScript.src);

    window.privacyPassLogin = async (url) => {
        // Open the wallet before anything else, while the click still allows
        // a popup.
        const wallet = window.open(walletURL, 'privacypass', 'popup,width=480,height=640');
        if (wallet === null) {
            throw new Error('the browser blocked the wallet popup');
        }
        try {
            const resp = await fetch(url, { method: 'POST' });
            const challenge = resp.headers.get('WWW-Authenticate')?.match(/challenge="?([\w=-]+)/)?.[1];
            if (resp.status !== 401 || challenge === undefined) {
                return resp;
            }
            const token = await requestToken(wallet, challenge);
            return await fetch(url, {
                method: 'POST',
                headers: { Authorization: `PrivateToken token="${token}"` },
            });
        } finally {
            wallet.close();
        }
    };

    // requestToken asks the wallet in the popup for a token for challenge.
    function requestToken(wallet, challenge) {
        return new Promise((resolve, reject) => {
            const finish = (settle, value) => {
                removeEventListener('message', onMessage);
                clearInterval(closedCheck);
                settle(value);
            };
            const onMessage = (e) => {
                if (e.source !== wallet || e.origin !== walletURL.origin) {
                    return;
                }
                switch (e.data?.type) {
                case 'privacypass-ready':
                    wallet.postMessage({ type: 'privacypass-request', challenge }, walletURL.origin);
                    break;
                case 'privacypass-token':
                    finish(resolve, e.data.token);
                    break;
                case 'privacypass-error':
                    finish(reject, new Error(e.data.error));
                    break;
                }
            };
            addEventListener('message', onMessage);
            const closedCheck = setInterval(() => {
                if (wallet.closed) {
                    finish(reject, new Error('the wallet was closed'));
                }
            }, 500);
        });
    }
})();

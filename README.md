
![icon](/firefox/icons/icon.svg)<!-- .element height="50px" width="50px" -->
# PwnFox

PwnFox is a Firefox/Burp extension that provide usefull 


![popup](/screenshots/popup.png)


## Features


###  Containers Profiles

PwnFox give you fast access to the Firefox containers. This allow you to have multiple identities in the same browser. 
When PwnFox and the `Add container header` option are enabled, PwnFox will automatically add a `X-PwnFox-Color` header to hightlight the query in Burp.

PwnFoxBurp will automatically highlight and strip the header, but you can also specify your own behavior with addons like logger++.

![tabs](/screenshots/tabs.png)
![burp](/screenshots/burp.png)



### PostMessage Logger

PwnFox add a new message tab in you devtool. This allow you to quickly visualize all postMessage between frames.

![](/screenshots/post-single.png)

You can also provide your own function to parse/filter the messages.
You get access to 3 arguments:
 * data -> the message data
 * origin -> the window object representing the origin
 * destion -> the window object representing the destination

You can return a string or a JSON serializable object.

![](/screenshots/post-dual.png)


### Toolbox(s)

Inject you own javascript code on page load. The code will be loaded as soon as possible. This can used to add dangerous behavior detection, or just to add extra function to your js console.

**Be carefull, the injected toolbox will run in the window context. Do not inject secret in untrusted domain.**


![settings](/screenshots/settings.png)


### Security header remover

Sometime it's easier to work with security header disabled. You can now do it with a single button press. Don't forget to reenable them before testing your final payload.

Headers stripped:
* Content-Security-Policy
* X-XSS-Protection
* X-Frame-Options
* X-Content-Type-Options


## Changelog

* v1.1.0
  * First public release

![icon](/firefox/icons/icon.svg)
# PwnFox

PwnFox is a Firefox/Burp extension that provide usefull 


![popup](/screenshots/popup.png)

## Features


###  Containers Profiles

PwnFox give you fast access to the Firefox containers. This allow you to have multiple identities in the same browser. 
When PwnFox and the `Add container header` option are enabled, PwnFox will automatically add a `X-PwnFox-Color` header to hightlight the query in Burp.

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

Inject you own javascript code on page load. The code will be loaded as soon as possible. This can used to add dangerous behavior detection, or just to add extra function to you js console.

**Be carefull, the injected toolbox will run in the window context. Do not inject secret in untrusted domain.**


![settings](/screenshots/settings.png)




async function main(){
    const features = new ContentScriptFeatures(config)
    features.maybeStart()
}

/* Dont wait for the window to load, we need to start as soon as possible to inject the toolbox early */
main()



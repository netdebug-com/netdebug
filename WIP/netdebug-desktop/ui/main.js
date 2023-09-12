function loadtab(element) {
    var container = document.getElementById("container");
    console.log("loadTab - ", element.rel);
    container.src = element.rel;

    var tabs = document.getElementById("tabs").getElementsByTagName("a");
    for (var i = 0; i < tabs.length; i++) {
        if (tabs[i].rel == element.rel) tabs[i].className = "selected";
        else tabs[i].className = "";
    }
}

function initTabs() {
    var tabs = document.getElementById("tabs").getElementsByTagName("a");
    var container = document.getElementById("container");
    container.src = tabs[0].rel;
    // force the onClick attribute here to avoid HTML loading time bugs?!
    for (var i = 0; i < tabs.length; i++) {
        tabs[i].addEventListener("click", (e) => {
            loadtab(e.target);
        });
    }
    console.log("initTabs(): done");
}

window.onload = initTabs;

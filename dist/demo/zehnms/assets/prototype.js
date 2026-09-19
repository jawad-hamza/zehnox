/*
 * ZehnMS prototype: visual niceties only. Nothing is saved, nothing is sent.
 * No fetch, no storage, works from file://.
 */
(function () {
    "use strict";

    // light the sidebar module and phone tab that match this page
    var here = document.body.getAttribute("data-module");
    if (here) {
        document.querySelectorAll("[data-module-link]").forEach(function (link) {
            if (link.getAttribute("data-module-link") === here) {
                link.classList.add("active");
                link.setAttribute("aria-current", "page");
            }
        });
    }

    function closeTips(except) {
        document.querySelectorAll(".k-tip.is-open").forEach(function (tip) {
            if (tip === except) { return; }
            tip.classList.remove("is-open");
            var body = tip.querySelector(".k-tip-body");
            var btn = tip.querySelector(".k-tip-btn");
            if (body) { body.hidden = true; }
            if (btn) { btn.setAttribute("aria-expanded", "false"); }
        });
    }

    document.addEventListener("click", function (event) {
        var target = event.target;

        // help tooltips open on click or tap
        var tipBtn = target.closest(".k-tip-btn");
        if (tipBtn) {
            var tip = tipBtn.closest(".k-tip");
            var body = tip.querySelector(".k-tip-body");
            var open = !tip.classList.contains("is-open");
            closeTips(tip);
            tip.classList.toggle("is-open", open);
            body.hidden = !open;
            tipBtn.setAttribute("aria-expanded", open ? "true" : "false");
            return;
        }
        if (!target.closest(".k-tip-body")) { closeTips(null); }

        // phone drawer
        if (target.closest("[data-drawer]")) {
            document.querySelector(".k-rail").classList.toggle("show");
            document.querySelector(".k-scrim").classList.toggle("show");
            return;
        }
        if (target.closest(".k-scrim")) {
            document.querySelector(".k-rail").classList.remove("show");
            document.querySelector(".k-scrim").classList.remove("show");
            return;
        }

        // show or hide an element by id (size picker, side panel)
        var toggler = target.closest("[data-toggle]");
        if (toggler) {
            event.preventDefault();
            var el = document.getElementById(toggler.getAttribute("data-toggle"));
            if (el) { el.hidden = !el.hidden; }
            if (toggler.hasAttribute("data-side")) {
                document.body.classList.toggle("body-side-hidden", el.hidden);
            }
            return;
        }

        // segmented switches (Cash / Bank / Credit, paper width)
        var seg = target.closest(".segmented > button");
        if (seg) {
            seg.parentNode.querySelectorAll("button").forEach(function (b) {
                b.classList.toggle("is-on", b === seg);
                b.setAttribute("aria-pressed", b === seg ? "true" : "false");
            });
            var label = seg.getAttribute("data-pay-label");
            var pay = document.getElementById("payLabel");
            if (label && pay) { pay.textContent = label; }
            return;
        }

        // grouped size family rows expand and fold
        var family = target.closest("[data-family]");
        if (family) {
            var name = family.getAttribute("data-family");
            var rows = document.querySelectorAll('[data-child-of="' + name + '"]');
            var show = rows.length && rows[0].hidden;
            rows.forEach(function (r) { r.hidden = !show; });
            var icon = family.querySelector(".twist i");
            if (icon) { icon.className = show ? "bi bi-chevron-down" : "bi bi-chevron-right"; }
            return;
        }

        // feature switches flip (locked ones stay put)
        var sw = target.closest(".switch:not(.locked)");
        if (sw) {
            sw.classList.toggle("on");
            sw.setAttribute("aria-checked", sw.classList.contains("on") ? "true" : "false");
        }
    });

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") {
            closeTips(null);
            var picker = document.getElementById("sizePicker");
            if (picker) { picker.hidden = true; }
        }
    });

    // forms never submit: this is a showcase
    document.addEventListener("submit", function (event) {
        var form = event.target;
        var next = form.getAttribute("data-next");
        event.preventDefault();
        if (next) { window.location.href = next; }
    });
})();

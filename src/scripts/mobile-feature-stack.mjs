export function nextFeatureIndex(current, count) {
    return count > 0 ? (current + 1) % count : 0;
}

export function featureLayer(index, current, count) {
    return count > 0 ? (index - current + count) % count : 0;
}

export function featureStackStyle(layer, count) {
    return {
        translateY: layer * 18,
        scale: Number((1 - layer * 0.035).toFixed(3)),
        opacity: Number((1 - layer * 0.06).toFixed(2)),
        zIndex: count - layer,
    };
}

export function initMobileStack(grid, { card = "[data-feature-card]", title = ".feature-title" } = {}) {
    const cards = Array.from(grid.querySelectorAll(card));
    if (cards.length < 2) return () => {};

    const media = window.matchMedia("(max-width: 760px)");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const controller = new AbortController();
    let current = 0;
    let locked = false;
    let hovered = false;
    let transitionTimer;
    let autoTimer;

    function clearAuto() {
        clearTimeout(autoTimer);
    }

    function scheduleAuto() {
        clearAuto();
        if (!media.matches || hovered || document.hidden) return;
        autoTimer = window.setTimeout(() => advance(), 4500);
    }

    function equalizeHeights() {
        cards.forEach((card) => {
            card.style.height = "auto";
        });
        const maxHeight = Math.max(...cards.map((card) => card.scrollHeight));
        if (maxHeight > 0) {
            cards.forEach((card) => {
                card.style.height = `${maxHeight}px`;
            });
        }
        return maxHeight;
    }

    function render() {
        const mobile = media.matches;
        grid.classList.toggle("is-feature-stack", mobile);

        if (!mobile) {
            clearAuto();
            grid.removeAttribute("aria-roledescription");
            grid.removeAttribute("aria-label");
            grid.style.removeProperty("--feature-stack-height");
            cards.forEach((card) => {
                delete card.dataset.featureLayer;
                card.classList.remove("is-stack-active", "is-exiting");
                card.style.removeProperty("height");
                card.style.removeProperty("transform");
                card.style.removeProperty("z-index");
                card.style.removeProperty("opacity");
                card.removeAttribute("tabindex");
                card.removeAttribute("role");
                card.removeAttribute("aria-current");
                card.removeAttribute("aria-hidden");
                card.removeAttribute("aria-label");
            });
            return;
        }

        grid.setAttribute("aria-roledescription", grid.dataset.stackRole ?? "carousel");
        grid.setAttribute("aria-label", grid.dataset.stackLabel ?? "");
        const maxHeight = equalizeHeights();

        cards.forEach((card, index) => {
            const layer = featureLayer(index, current, cards.length);
            const style = featureStackStyle(layer, cards.length);
            const label = card.querySelector(title)?.textContent?.trim() ?? "";
            card.dataset.featureLayer = String(layer);
            card.style.transform = `translateY(${style.translateY}px) scale(${style.scale})`;
            card.style.zIndex = String(style.zIndex);
            card.style.opacity = String(style.opacity);
            card.classList.toggle("is-stack-active", layer === 0);
            card.tabIndex = layer === 0 ? 0 : -1;
            card.setAttribute("role", "button");
            card.setAttribute("aria-current", layer === 0 ? "true" : "false");
            card.setAttribute("aria-hidden", layer === 0 ? "false" : "true");
            if (layer === 0) {
                card.setAttribute("aria-label", `${label}. ${grid.dataset.stackHint ?? ""}`.trim());
            } else {
                card.removeAttribute("aria-label");
            }
        });

        grid.style.setProperty("--feature-stack-height", `${maxHeight + (cards.length - 1) * 18}px`);
    }

    function advance(restoreFocus = false) {
        clearAuto();
        if (locked || !media.matches) return;
        locked = true;
        const outgoing = cards[current];
        outgoing.classList.add("is-exiting");
        const duration = reducedMotion.matches ? 0 : 440;
        clearTimeout(transitionTimer);
        transitionTimer = window.setTimeout(() => {
            current = nextFeatureIndex(current, cards.length);
            outgoing.classList.remove("is-exiting");
            render();
            if (restoreFocus) cards[current]?.focus({ preventScroll: true });
            locked = false;
            scheduleAuto();
        }, duration);
    }

    cards.forEach((card, index) => {
        card.addEventListener(
            "click",
            () => {
                if (!media.matches || locked) return;
                if (index === current) {
                    advance();
                    return;
                }
                clearAuto();
                current = index;
                render();
                scheduleAuto();
            },
            { signal: controller.signal },
        );
        card.addEventListener(
            "keydown",
            (event) => {
                if (index !== current || (event.key !== "Enter" && event.key !== " ")) return;
                event.preventDefault();
                advance(true);
            },
            { signal: controller.signal },
        );
    });

    media.addEventListener(
        "change",
        () => {
            locked = false;
            clearTimeout(transitionTimer);
            cards.forEach((card) => card.classList.remove("is-exiting"));
            render();
            scheduleAuto();
        },
        { signal: controller.signal },
    );
    window.addEventListener("resize", render, { signal: controller.signal });
    grid.addEventListener(
        "mouseenter",
        () => {
            hovered = true;
            clearAuto();
        },
        { signal: controller.signal },
    );
    grid.addEventListener(
        "mouseleave",
        () => {
            hovered = false;
            scheduleAuto();
        },
        { signal: controller.signal },
    );
    document.addEventListener(
        "visibilitychange",
        () => {
            if (document.hidden) clearAuto();
            else scheduleAuto();
        },
        { signal: controller.signal },
    );

    const cleanup = () => {
        clearAuto();
        clearTimeout(transitionTimer);
        controller.abort();
    };
    document.addEventListener("astro:before-swap", cleanup, { once: true, signal: controller.signal });
    render();
    scheduleAuto();
    return cleanup;
}

export function initAllMobileStacks(root = document) {
    root.querySelectorAll("[data-feature-stack]").forEach((grid) => {
        initMobileStack(grid, {
            card: grid.dataset.stackCard || "[data-feature-card]",
            title: grid.dataset.stackTitle || ".feature-title",
        });
    });
}

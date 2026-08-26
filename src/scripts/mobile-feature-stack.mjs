export function nextFeatureIndex(current, count) {
    return count > 0 ? (current + 1) % count : 0;
}

export function featureLayer(index, current, count) {
    return count > 0 ? (index - current + count) % count : 0;
}

let activeCleanup = null;

export function initMobileFeatureStack(root = document) {
    activeCleanup?.();
    const grid = root.querySelector("[data-feature-stack]");
    if (!grid) return () => {};

    const cards = Array.from(grid.querySelectorAll("[data-feature-card]"));
    const media = window.matchMedia("(max-width: 760px)");
    const controller = new AbortController();
    let current = 0;
    let locked = false;
    let unlockTimer;

    function render() {
        const mobile = media.matches;
        let maxHeight = 0;
        grid.classList.toggle("is-feature-stack", mobile);

        if (mobile) {
            grid.setAttribute("aria-roledescription", grid.dataset.stackRole ?? "carousel");
            grid.setAttribute("aria-label", grid.dataset.stackLabel ?? "");
        } else {
            grid.removeAttribute("aria-roledescription");
            grid.removeAttribute("aria-label");
        }

        cards.forEach((card, index) => {
            const layer = featureLayer(index, current, cards.length);
            if (mobile) {
                const title = card.querySelector(".feature-title")?.textContent?.trim() ?? "";
                card.dataset.featureLayer = String(layer);
                card.tabIndex = layer === 0 ? 0 : -1;
                card.setAttribute("role", layer === 0 ? "button" : "article");
                card.setAttribute("aria-current", layer === 0 ? "true" : "false");
                card.setAttribute("aria-hidden", layer > 2 ? "true" : "false");
                if (layer === 0) {
                    card.setAttribute("aria-label", `${title}. ${grid.dataset.stackHint ?? ""}`.trim());
                } else {
                    card.removeAttribute("aria-label");
                }
                maxHeight = Math.max(maxHeight, card.scrollHeight);
            } else {
                delete card.dataset.featureLayer;
                card.removeAttribute("tabindex");
                card.removeAttribute("role");
                card.removeAttribute("aria-current");
                card.removeAttribute("aria-hidden");
                card.removeAttribute("aria-label");
            }
        });

        if (mobile) grid.style.setProperty("--feature-stack-height", `${maxHeight + 40}px`);
        else grid.style.removeProperty("--feature-stack-height");
    }

    function advance(card) {
        if (locked) return;
        if (!media.matches || card.dataset.featureLayer !== "0") return;
        locked = true;
        current = nextFeatureIndex(current, cards.length);
        render();
        cards[current]?.focus({ preventScroll: true });
        clearTimeout(unlockTimer);
        unlockTimer = window.setTimeout(() => {
            locked = false;
        }, 280);
    }

    cards.forEach((card) => {
        card.addEventListener("click", () => advance(card), { signal: controller.signal });
        card.addEventListener(
            "keydown",
            (event) => {
                if (event.key !== "Enter" && event.key !== " ") return;
                event.preventDefault();
                advance(card);
            },
            { signal: controller.signal },
        );
    });

    media.addEventListener(
        "change",
        () => {
            current = 0;
            locked = false;
            render();
        },
        { signal: controller.signal },
    );
    window.addEventListener("resize", render, { signal: controller.signal });

    const cleanup = () => {
        clearTimeout(unlockTimer);
        controller.abort();
        activeCleanup = null;
    };
    document.addEventListener("astro:before-swap", cleanup, { once: true, signal: controller.signal });
    activeCleanup = cleanup;
    render();
    return cleanup;
}

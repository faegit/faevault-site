export function nextFeatureIndex(current, count) {
    return count > 0 ? (current + 1) % count : 0;
}

export function featureLayer(index, current, count) {
    return count > 0 ? (index - current + count) % count : 0;
}

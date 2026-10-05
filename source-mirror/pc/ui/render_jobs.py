"""Bounded workers for expensive read-only detail rendering."""

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import multiprocessing
import threading


markdown_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vault-markdown")
thumbnail_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vault-thumbnail")
_markdown_process = None
_process_lock = threading.Lock()


def render_document(text: str, colors: dict) -> str:
    """Keep CPU-heavy Python parsing out of the GUI interpreter for long notes."""
    from core.markdown_html import render_markdown_document

    if len(text) < 64 * 1024:
        return render_markdown_document(text, colors)
    global _markdown_process
    with _process_lock:
        if _markdown_process is None:
            _markdown_process = ProcessPoolExecutor(
                max_workers=1, mp_context=multiprocessing.get_context("spawn"),
                max_tasks_per_child=16,
            )
    return _markdown_process.submit(render_markdown_document, text, colors).result()

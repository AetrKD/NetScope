css_content = """
/* AI Markdown Result Styles */
.markdown-body {
    font-family: var(--font-body);
    font-size: 0.95rem;
    line-height: 1.6;
    color: var(--text-primary);
}
.markdown-body h1, .markdown-body h2, .markdown-body h3, .markdown-body h4 {
    color: var(--accent-blue);
    margin-top: 1.2em;
    margin-bottom: 0.5em;
    font-family: var(--font-heading);
    font-weight: 600;
}
.markdown-body h1 { font-size: 1.4rem; border-bottom: 1px solid var(--border-strong); padding-bottom: 0.3em; color: var(--accent-cyan); }
.markdown-body h2 { font-size: 1.2rem; border-bottom: 1px solid var(--border-medium); padding-bottom: 0.2em; }
.markdown-body h3 { font-size: 1.05rem; }
.markdown-body p { margin-bottom: 1em; }
.markdown-body ul, .markdown-body ol {
    margin-bottom: 1em;
    padding-left: 2em;
}
.markdown-body li { margin-bottom: 0.3em; }
.markdown-body li > ul, .markdown-body li > ol { margin-top: 0.3em; margin-bottom: 0; }
.markdown-body strong { font-weight: 700; color: var(--accent-purple); }
.markdown-body em { font-style: italic; color: var(--accent-amber); }
.markdown-body code {
    background: rgba(0,0,0,0.4);
    padding: 0.2em 0.4em;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 0.85em;
    color: var(--accent-green);
}
.markdown-body pre {
    background: #000;
    padding: 1em;
    border-radius: var(--radius-sm);
    overflow-x: auto;
    margin-bottom: 1em;
    border: 1px solid var(--border-medium);
}
.markdown-body pre code { background: none; padding: 0; color: #fff; }
.markdown-body blockquote {
    border-left: 4px solid var(--accent-purple);
    color: var(--text-secondary);
    margin: 1em 0;
    background: rgba(139, 92, 246, 0.1);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    padding: 0.5em 1em;
}
"""

with open('static/css/style.css', 'a', encoding='utf-8') as f:
    f.write(css_content)

// Custom styles: a sheet the admin pastes in the settings page, applied to this browser only.
// Typography this specific has no place in the shipped stylesheet, and the console cannot be
// reached by a user-style extension the way a website can.
(function () {
  'use strict';
  var STORAGE_KEY = 'sevenmirror.customCss';
  var DEFAULT_CSS = 'body,\ninput,\ntextarea,\nkeygen,\nselect,\nbutton {\n  text-shadow: 0px 0px 1px rgba(0, 0, 0, 0.16) !important;\n  -webkit-font-smoothing: subpixel-antialiased !important;\n  font-family: \'Microsoft Yahei\';\n}\n@font-face {\n  font-family: \'Microsoft YaHei\';\n  src: local(\'Microsoft Yahei\');\n}\n@font-face {\n  font-family: \'Microsoft YaHei\';\n  src: local(\'Segoe UI\');\n}\n@font-face {\n  font-family: \'微软雅黑\';\n  src: local(\'Microsoft Yahei\');\n}\n@font-face {\n  font-family: \'微软雅黑\';\n  src: local(\'Segoe UI\');\n}\n@font-face {\n  font-family: \'Segoe UI\';\n  src: local(\'Microsoft Yahei\');\n}\n@font-face {\n  font-family: \'Segoe UI\';\n  src: local(\'Segoe UI\');\n}';

  function stored() {
    try {
      var value = window.localStorage.getItem(STORAGE_KEY);
      return typeof value === 'string' && value.length > 0 ? value : DEFAULT_CSS;
    } catch (error) {
      return DEFAULT_CSS;
    }
  }

  // The page forbids inline styles, so the sheet is handed to the browser as a blob stylesheet and
  // swapped in through a link element.
  var sheetUrl = null;

  function inject(css) {
    var link = document.getElementById('custom-css');
    if (!link) {
      link = document.createElement('link');
      link.id = 'custom-css';
      link.rel = 'stylesheet';
      document.head.appendChild(link);
    }
    if (sheetUrl !== null) {
      window.URL.revokeObjectURL(sheetUrl);
    }
    sheetUrl = window.URL.createObjectURL(new Blob([css], { type: 'text/css' }));
    link.href = sheetUrl;
  }

  inject(stored());

  document.addEventListener('DOMContentLoaded', function () {
    var editor = document.getElementById('custom-css-input');
    if (!editor) return;
    var status = document.getElementById('custom-css-status');
    editor.value = stored();

    function flash(text) {
      if (!status) return;
      status.textContent = text;
      status.hidden = false;
      window.setTimeout(function () { status.hidden = true; }, 2500);
    }

    var save = document.getElementById('save-custom-css');
    if (save) {
      save.addEventListener('click', function () {
        // An emptied box means the default sheet, the same way the field starts out.
        var value = editor.value.trim().length === 0 ? DEFAULT_CSS : editor.value;
        try {
          window.localStorage.setItem(STORAGE_KEY, value);
        } catch (error) {
          return;
        }
        inject(value);
        flash('已保存');
      });
    }

    // Both buttons only rewrite the box; the sheet goes live when it is saved.
    var restore = document.getElementById('restore-custom-css');
    if (restore) restore.addEventListener('click', function () { editor.value = DEFAULT_CSS; });
    var clear = document.getElementById('clear-custom-css');
    if (clear) clear.addEventListener('click', function () { editor.value = ''; });
  });
})();

import { EditorState } from "@codemirror/state";
import { EditorView, basicSetup } from "codemirror";
import { StreamLanguage } from "@codemirror/language";
import { toml } from "@codemirror/legacy-modes/mode/toml";

// We want to export an initializer function so the HTML page can pass in the element and the initial raw TOML String
window.createTomlEditor = function(elementId, initialDoc, updateCallback) {
  const initialState = EditorState.create({
    doc: initialDoc,
    extensions: [
      basicSetup,
      StreamLanguage.define(toml),
      EditorView.updateListener.of((update) => {
        if (update.docChanged && updateCallback) {
          updateCallback(update.state.doc.toString());
        }
      })
    ]
  });

  return new EditorView({
    state: initialState,
    parent: document.getElementById(elementId)
  });
};

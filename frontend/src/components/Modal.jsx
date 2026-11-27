import React, { useEffect, useLayoutEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

const modalStack = [];

export default function Modal({ title, children, onClose, wide = false, drawer = false, className = "", closeOnMask = false, scrollRef = null, onScroll = null, headerActions = null }) {
  const box = useRef(null);
  const scrollTop = useRef(0);
  const modalId = useRef(Symbol("modal"));
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    const id = modalId.current;
    modalStack.push(id);
    const close = (event) => {
      if (event.key !== "Escape" || modalStack[modalStack.length - 1] !== id) return;
      if (document.querySelector(".terminal-file-menu")) return;
      event.preventDefault();
      onCloseRef.current();
    };
    window.addEventListener("keydown", close);
    return () => {
      window.removeEventListener("keydown", close);
      const index = modalStack.lastIndexOf(id);
      if (index >= 0) modalStack.splice(index, 1);
    };
  }, []);
  useLayoutEffect(() => {
    if (box.current && Math.abs(box.current.scrollTop - scrollTop.current) > 2) box.current.scrollTop = scrollTop.current;
  });
  return createPortal(
    <div className={`modal-mask ${drawer ? "drawer-mask" : ""}`} onMouseDown={(event) => closeOnMask && event.target === event.currentTarget && onClose()}>
      <div ref={(node) => { box.current = node; if (scrollRef) scrollRef.current = node; }} onScroll={(event) => { scrollTop.current = event.currentTarget.scrollTop; onScroll?.(event); }} className={`modal ${wide ? "wide" : ""} ${drawer ? "drawer" : ""} ${className}`.trim()} role="dialog" aria-modal="true">
        <div className="modal-head"><h3>{title}</h3><div className="modal-head-actions">{headerActions}<button className="icon" title="关闭（Esc）" onClick={onClose}><X /></button></div></div>
        {children}
      </div>
    </div>,
    document.body,
  );
}

window.__ModuleLoader__.load({
	id: "dsh-cyber-redteam",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		let react_jsx_runtime = require("react/jsx-runtime");
		let react = require("react");
		//#region \0soa-css:dsh-cyber-redteam/RedTeamToggle.module.css
		const css = ".soaCyb_wrap{align-items:center;gap:6px;display:inline-flex}.soaCyb_chip{corner-shape:round;background:var(--dsw-alias-interactive-bg-hover);min-width:34px;color:var(--dsw-alias-label-primary);cursor:pointer;border:none;border-radius:999px;align-items:center;gap:5px;padding:2px 9px;font-size:13px;font-weight:500;line-height:20px;display:inline-flex}.soaCyb_chip:hover:not(:disabled){color:var(--dsw-alias-label-primary)}.soaCyb_chip:focus-visible{outline:2px solid var(--dsw-alias-label-primary);outline-offset:2px}.soaCyb_armed{background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-label)}.soaCyb_armed:hover:not(:disabled){color:var(--dsw-alias-state-warn-primary)}.soaCyb_disabled{opacity:.55;cursor:default}.soaCyb_icon{flex:none;display:block}.soaCyb_error{color:var(--dsw-alias-state-error-primary);font-size:12px;line-height:18px}";
		const tagId = "dsh-cyber-redteam/RedTeamToggle.module.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "dsh-cyber-redteam";
			tag.dataset.pluginCss = tagId;
			tag.textContent = css;
			document.head.appendChild(tag);
		}
		const classes = {
			wrap: "soaCyb_wrap",
			chip: "soaCyb_chip",
			armed: "soaCyb_armed",
			disabled: "soaCyb_disabled",
			error: "soaCyb_error"
		};
		//#endregion
		//#region lib/types/client/status.js
		/**
		* Stable status contract shared with the host's `cyberModeText`. The host
		* returns a human line whose prefix is always `cyber-mode: on|off|unavailable`,
		* so the toggle reads state from that prefix instead of guessing.
		*/
		const STATUS_PATTERN = /cyber-mode:\s*(on|off|unavailable)/iu;
		/**
		* Parse a command result line into a toggle state.
		* @param text - the command's `text` payload, if any.
		* @returns `"on"`, `"off"`, or `"unavailable"`.
		*/
		function parseStatus(text) {
			const match = STATUS_PATTERN.exec(typeof text === "string" ? text : "");
			return match === null ? "unavailable" : match[1].toLowerCase();
		}
		/**
		* Run one `/cyber-mode` line over the commands Remote.
		* @param ctx - client root context.
		* @param sessionId - the session the composer belongs to.
		* @param line - the command line to execute.
		* @returns the resulting toggle state.
		*/
		async function runCommand(ctx, sessionId, line) {
			try {
				const result = await ctx.remote.commands.execute(sessionId, line, []);
				if (!result.ok) return "unavailable";
				const value = result.value;
				if (value === void 0 || value === null || typeof value !== "object") return "unavailable";
				// DSH 0.1.5 wraps a command outcome as { commandId, result: { kind, text } };
				// the human line the toggle parses lives one level deeper than `value`.
				const outcome = value.result;
				if (outcome === void 0 || outcome === null || typeof outcome !== "object") return "unavailable";
				return parseStatus(outcome.text);
			} catch {
				return "unavailable";
			}
		}
		//#endregion
		//#region lib/types/client/RedTeamToggle.js
		/** Minimal shield mark, drawn inline so the plugin carries no icon dependency. */
		function ShieldIcon() {
			return react_jsx_runtime.jsx("svg", {
				className: classes.icon,
				width: 12,
				height: 12,
				viewBox: "0 0 24 24",
				fill: "none",
				"aria-hidden": "true",
				children: react_jsx_runtime.jsx("path", {
					d: "M12 2.5 4.8 5.4v6.1c0 4.5 3.1 8.6 7.2 9.9 4.1-1.3 7.2-5.4 7.2-9.9V5.4L12 2.5Zm0 2.2 4.9 2v4.8c0 3.2-2 6.4-4.9 7.6-2.9-1.2-4.9-4.4-4.9-7.6V6.7l4.9-2Z",
					fill: "currentColor"
				})
			});
		}
		/**
		* Composer control that arms or disarms CyberOps red-team mode for the
		* session. State comes from the host (never client optimism): mount asks
		* for `status`, each click asks for `on`/`off` and re-reads the answer.
		* @param props - host-supplied `control` plus the locale `t`.
		* @returns the toggle chip, or null while the first status is unknown.
		*/
		function RedTeamToggle({ t, control }) {
			const [state, setState] = react.useState(null);
			const [busy, setBusy] = react.useState(false);
			const [error, setError] = react.useState(null);
			const aliveRef = react.useRef(true);
			react.useEffect(() => {
				aliveRef.current = true;
				return () => {
					aliveRef.current = false;
				};
			}, []);
			react.useEffect(() => {
				let cancelled = false;
				control.status().then((next) => {
					if (!cancelled && aliveRef.current) setState(next);
				}, () => {
					if (!cancelled && aliveRef.current) setState("unavailable");
				});
				return () => {
					cancelled = true;
				};
			}, [control]);
			if (state === null) return null;
			const armed = state === "on";
			const unavailable = state === "unavailable";
			const title = unavailable ? t("chip.unavailable") : armed ? t("chip.on.title") : t("chip.off.title");
			const toggle = () => {
				if (busy || unavailable) return;
				setBusy(true);
				setError(null);
				control.set(!armed).then((next) => {
					if (!aliveRef.current) return;
					setBusy(false);
					setState(next);
				}, (reason) => {
					if (!aliveRef.current) return;
					setBusy(false);
					setError(reason instanceof Error ? reason.message : String(reason));
				});
			};
			return react_jsx_runtime.jsxs("span", {
				className: classes.wrap,
				children: [react_jsx_runtime.jsxs("button", {
					type: "button",
					className: [classes.chip, armed ? classes.armed : "", unavailable ? classes.disabled : ""].filter(Boolean).join(" "),
					"aria-pressed": armed,
					"aria-label": title,
					title,
					disabled: busy || unavailable,
					onClick: toggle,
					children: [react_jsx_runtime.jsx(ShieldIcon, {}), react_jsx_runtime.jsx("span", { children: t("chip.label") })]
				}), error !== null && react_jsx_runtime.jsx("span", {
					className: classes.error,
					role: "status",
					title: error,
					children: t("failed")
				})]
			});
		}
		//#endregion
		//#region lib/types/client/locales.js
		/** `cyber` namespace dictionaries (the composer red-team toggle's copy). */
		/** Simplified Chinese dictionary (the key-set source of truth). */
		const zh = {
			"chip.label": "红队",
			"chip.on.title": "Red Team 模式已开启 — 点击关闭（/cyber-mode off）",
			"chip.off.title": "Red Team 模式已关闭 — 点击开启（/cyber-mode on）",
			"chip.unavailable": "Red Team 不可用：CyberOps 工具包缺失或校验失败",
			"failed": "切换 Red Team 失败"
		};
		/** English dictionary, checked complete against the zh key set. */
		const en = {
			"chip.label": "Red Team",
			"chip.on.title": "Red Team mode on — click to turn off (/cyber-mode off)",
			"chip.off.title": "Red Team mode off — click to turn on (/cyber-mode on)",
			"chip.unavailable": "Red Team unavailable: the CyberOps toolkit is missing or failed verification",
			"failed": "Failed to toggle Red Team mode"
		};
		//#endregion
		//#region lib/types/client/index.js
		/** Dictionary namespace owned by this plugin. */
		const NS = "cyber";
		/** Required services: slot registry, commands Remote, and locale registry. */
		const inject = [
			"slots",
			"remote",
			"remote.commands",
			"locale"
		];
		/**
		* Client plugin body: register the red-team toggle over the command channel.
		* @param ctx - client root context.
		*/
		function apply(ctx) {
			ctx.effect(() => ctx.locale.register(NS, {
				zh,
				en
			}), "ui-cyber: dictionaries");
			ctx.slots.inject("conversation.input.right", () => ctx.slots.register({
				name: "conversation.input.right",
				id: "cyber-mode",
				order: 20,
				locale: NS,
				inject: (sessionId) => ({ control: {
					status: () => runCommand(ctx, sessionId, "/cyber-mode status"),
					set: (on) => runCommand(ctx, sessionId, on ? "/cyber-mode on" : "/cyber-mode off")
				} })
			}, RedTeamToggle));
		}
		//#endregion
		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});

//# sourceMappingURL=client.js.map

window.__ModuleLoader__.load({
	id: "dsh-subagent-guard",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		// 浏览器半边：由模块加载器物化的 CJS 包，`require` 认得平台种子（含 react）。
		const React = require("react");
		const h = React.createElement;

		/** profile 里的 Loader entry id，同时也是 settings 的命名空间。 */
		const ENTRY = "dsh-subagent-guard";

		const S_BOX = {
			border: "0.5px solid var(--dsw-alias-border-l2, #333)",
			borderRadius: "10px",
			padding: "4px 14px",
			margin: "6px 0 10px",
		};
		const S_HINT = { margin: "0 0 2px", fontSize: "12px", lineHeight: "18px", opacity: 0.66 };
		const S_ROW = { display: "flex", alignItems: "flex-start", gap: "10px", padding: "7px 0" };
		const S_TITLE = { fontSize: "14px", lineHeight: "20px" };
		const S_SUB = { fontSize: "12px", lineHeight: "17px", opacity: 0.6 };

		function Toggle(props) {
			return h(
				"label",
				{ style: { ...S_ROW, cursor: props.disabled ? "default" : "pointer", opacity: props.disabled ? 0.5 : 1 } },
				h("input", {
					type: "checkbox",
					checked: props.checked,
					disabled: props.disabled,
					style: { marginTop: "3px" },
					onChange: (event) => props.onChange(event.target.checked),
				}),
				h(
					"span",
					{ style: { display: "flex", flexDirection: "column", gap: "1px" } },
					h("span", { style: S_TITLE }, props.title),
					h("span", { style: S_SUB }, props.hint),
				),
			);
		}

		/** 造一个绑到真实配置的卡片组件；`ctx` 在 apply 时捕获。 */
		function makeCard(ctx) {
			const form = ctx.configForms.get(ENTRY);
			const read = () => form.getSnapshot();
			const subscribe = (onChange) => form.subscribe(onChange);

			return function GuardConfigCard() {
				const snap = React.useSyncExternalStore(subscribe, read, read);
				const value = (snap && snap.value) || {};
				const writable = !(snap && snap.writable === false);
				const busy = snap && snap.status !== undefined && snap.status !== "ready";
				const disabled = !writable || busy;
				// Q1-6（red-4b）：快照还没就绪 / 命名空间不可用时，checkbox 会显示成
				// “默认开”，容易被当成真实生效值。这里明说一句，别让人看错。
				const loaded =
					typeof value.enforceToolFace === "boolean" &&
					typeof value.enforceSandbox === "boolean";

				const on = (field, fallback) =>
					typeof value[field] === "boolean" ? value[field] : fallback;
				// Q2/Q3（red-4b）：写入失败曾被 `.catch(() => {})` 吞掉，界面只会静默
				// 回弹。这里显式说出来——开关是安全姿态，改不动必须让人知道。
				const [writeError, setWriteError] = React.useState(null);
				const set = (field, next) => {
					setWriteError(null);
					Promise.resolve(form.set(field, next))
						.then((accepted) => {
							if (accepted === false) setWriteError("写入被宿主拒绝，已回滚到上一次的值。");
						})
						.catch(() => setWriteError("写入失败：宿主没有接受这次修改。"));
				};

				return h(
					"section",
					null,
					h("h3", { style: { margin: "0 0 2px", fontSize: "15px", fontWeight: 600 } }, "拦截开关"),
					h(
						"p",
						{ style: S_HINT },
						"这里只放“要不要拦”的总策略；具体规则与工具清单交给 Agent 调整。",
					),
					loaded
						? null
						: h(
								"p",
								{ style: { ...S_HINT, opacity: 0.8 } },
								"正在读取配置；下面显示的是默认值，暂不可改。",
							),
					writeError
						? h(
								"p",
								{ style: { ...S_HINT, color: "var(--dsw-alias-state-error-primary, #d9534f)" } },
								writeError,
							)
						: null,
					h(
						"div",
						{ style: S_BOX },
						h(Toggle, {
							title: "工具面拦截（由父 Agent 指定）",
							hint: "打开：父 Agent 派子代理时指定的工具面生效。关闭：忽略它；有部署上限时仍压到白名单，否则继承完整面。",
							checked: on("enforceToolFace", true),
							disabled,
							onChange: (v) => set("enforceToolFace", v),
						}),
						h(Toggle, {
							title: "权限拦截（由父 Agent 指定）",
							hint: "打开：子代理的沙箱档位被压到配置上限。关闭：完全跟随父会话的档位。",
							checked: on("enforceSandbox", true),
							disabled,
							onChange: (v) => set("enforceSandbox", v),
						}),
					),
				);
			};
		}

		function apply(ctx) {
			// 槽是**动态声明**的：插件页挂载时才存在，直接 register 会静默落空。
			ctx.effect(() =>
				ctx.slots.inject("plugins.bundle.config", () =>
					ctx.slots.register(
						{
							name: "plugins.bundle.config",
							key: ENTRY,
							order: 10,
						},
						makeCard(ctx),
					),
				),
			);
		}

		exports.apply = apply;
		exports.inject = ["slots", "configForms"];
		return module.exports;
	},
});

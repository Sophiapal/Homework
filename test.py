# -*- coding: utf-8 -*-
"""
GUI-версія мінімальної онтології "Кулінарія" (рефакторинг імен змінних/функцій):
- рівно 20 класів;
- 3 відношення: is_a, part_of, belongs_to;
- ≥4 рівні ієрархії за is_a;
- 2+ інстанси на кожен листовий клас (харчовий об'єкт);
- відповіді формуються автоматичним аналізом зв'язків (шлях + пояснення).

Запуск: python cooking_ontology_refactored.py
"""

from __future__ import annotations
from collections import defaultdict, deque
from typing import Dict, Set, Tuple, List
import tkinter as tk
from tkinter import ttk, messagebox
import re

# 1) КЛАСИ ТА ВІДНОШЕННЯ
# is_a: (child_class, parent_class)
IS_A_EDGES: Set[Tuple[str, str]] = {
    ("їжа", "сутність"),
    ("інгредієнт", "їжа"),
    ("страва", "їжа"),

    ("овоч", "інгредієнт"),
    ("фрукт", "інгредієнт"),
    ("м'ясо", "інгредієнт"),
    ("молочний_продукт", "інгредієнт"),

    ("морква", "овоч"),
    ("томат", "овоч"),
    ("лимон", "фрукт"),
    ("полуниця", "фрукт"),
    ("яловичина", "м'ясо"),
    ("курка", "м'ясо"),
    ("сир", "молочний_продукт"),
    ("молоко", "молочний_продукт"),

    ("піца", "страва"),
    ("борщ", "страва"),
    ("торт", "страва"),

    ("кухня", "сутність"),
}

# part_of: (part, whole)
PART_OF_EDGES: Set[Tuple[str, str]] = {
    ("томат", "піца"),
    ("сир", "піца"),
    ("морква", "борщ"),
    ("молоко", "торт"),
}

# belongs_to: (dish_class, cuisine_instance)
BELONGS_TO_EDGES: Set[Tuple[str, str]] = {
    ("піца", "італійська_кухня"),
    ("борщ", "українська_кухня"),
    ("торт", "французька_кухня"),
}

# instance mapping: instance_name -> class_name
INSTANCES: Dict[str, str] = {
    "carrot_1": "морква", "carrot_2": "морква",
    "tomato_1": "томат", "tomato_2": "томат",
    "lemon_1": "лимон", "lemon_2": "лимон",
    "strawberry_1": "полуниця", "strawberry_2": "полуниця",
    "beef_1": "яловичина", "beef_2": "яловичина",
    "chicken_1": "курка", "chicken_2": "курка",
    "cheese_1": "сир", "cheese_2": "сир",
    "milk_1": "молоко", "milk_2": "молоко",
    "pizza_1": "піца", "pizza_2": "піца",
    "borscht_1": "борщ", "borscht_2": "борщ",
    "cake_1": "торт", "cake_2": "торт",

    # кухні як інстанси класу "кухня"
    "італійська_кухня": "кухня",
    "українська_кухня": "кухня",
    "французька_кухня": "кухня",
}

# 2) ІНДЕКСИ ДЛЯ is_a (для швидкого доступу до батьків/дітей у ієрархії)
ISA_CHILDREN_INDEX: Dict[str, Set[str]] = defaultdict(set)
ISA_PARENTS_INDEX: Dict[str, Set[str]] = defaultdict(set)
for child_class, parent_class in IS_A_EDGES:
    ISA_CHILDREN_INDEX[parent_class].add(child_class)
    ISA_PARENTS_INDEX[child_class].add(parent_class)

# 3) ПОБУДОВА МІЧЕНИХ РЕБЕР ГРАФА

def build_labeled_edges() -> List[Tuple[str, str, str]]:
    """Повертає список орієнтованих ребер (src, dst, label) для всіх відношень (включно з оберненими)."""
    edges: List[Tuple[str, str, str]] = []

    # is_a та обернене is_a↑
    for child_class, parent_class in IS_A_EDGES:
        edges.append((child_class, parent_class, "is_a"))
        edges.append((parent_class, child_class, "is_a↑"))

    # part_of та обернене has_part
    for part_node, whole_node in PART_OF_EDGES:
        edges.append((part_node, whole_node, "part_of"))
        edges.append((whole_node, part_node, "has_part"))

    # belongs_to та обернене belongs_to↑
    for dish_class, cuisine in BELONGS_TO_EDGES:
        edges.append((dish_class, cuisine, "belongs_to"))
        edges.append((cuisine, dish_class, "belongs_to↑"))

    # зв’язки клас–інстанс (instance та instance↑)
    for instance_name, class_name in INSTANCES.items():
        edges.append((instance_name, class_name, "instance"))
        edges.append((class_name, instance_name, "instance↑"))

    return edges

LABELED_EDGES: List[Tuple[str, str, str]] = build_labeled_edges()

# 4) ЛОГІКА ВИСНОВКІВ

def normalize_id(text: str) -> str:
    """Нормалізує введений ідентифікатор: обрізає зайві пробіли/лапки, 
    знижує регістр, замінює пробіли на підкреслення."""
    return text.strip().strip('"').strip("'").lower().replace(" ", "_")

def is_subclass_of(child: str, parent: str) -> bool:
    """True, якщо `child` є підкласом `parent` (через 0+ кроків по is_a)."""
    visited: Set[str] = set()
    queue: deque[str] = deque([child])
    while queue:
        current = queue.popleft()
        if current == parent:
            return True
        for direct_parent in ISA_PARENTS_INDEX.get(current, ()):  # рух вгору по ієрархії
            if direct_parent not in visited:
                visited.add(direct_parent)
                queue.append(direct_parent)
    return False

def is_leaf_class(class_name: str) -> bool:
    """Листовий клас — той, що не має нащадків (немає дітей у відношенні is_a)."""
    return len(ISA_CHILDREN_INDEX.get(class_name, ())) == 0

def get_practical_leaf_classes() -> List[str]:
    """Повертає відсортований список листових класів, які є підкласами 'їжа'."""
    all_nodes = {c for c, _ in IS_A_EDGES} | {p for _, p in IS_A_EDGES}
    leaf_food_classes = [
        cls for cls in all_nodes 
        if is_leaf_class(cls) and is_subclass_of(cls, "їжа")
    ]
    return sorted(leaf_food_classes)

def find_labeled_path(src: str, dst: str) -> List[Tuple[str, str | None]]:
    """
    Пошук шляху між двома вузлами в графі знань (онто-графі).
    Повертає список кортежів (node, edge_label_from_node), що описують шлях 
    від src до dst. Останній елемент має edge_label None (досягнуто dst).
    Порожній список означає відсутність зв’язку.
    """
    if src == dst:
        return [(src, None)]
    visited: Set[str] = {src}
    queue: deque[Tuple[str, List[Tuple[str, str | None]]]] = deque([(src, [])])
    while queue:
        current_node, path = queue.popleft()
        for edge_src, edge_dst, edge_label in LABELED_EDGES:
            if edge_src != current_node or edge_dst in visited:
                continue
            new_path = path + [(edge_src, edge_label)]
            if edge_dst == dst:
                return new_path + [(edge_dst, None)]
            visited.add(edge_dst)
            queue.append((edge_dst, new_path))
    return []

# Словник для україномовних міток відношень (для пояснення)
LABELS_UA: Dict[str, str] = {
    "is_a": "is_a (узагальнення)",
    "is_a↑": "is_a (спеціалізація)",
    "part_of": "part_of (частина→ціле)",
    "has_part": "has_part (ціле→частина)",
    "belongs_to": "belongs_to (належить_до)",
    "belongs_to↑": "belongs_to↑",
    "instance": "instance",
    "instance↑": "instance↑",
}

def explain_relationship(a: str, b: str) -> str:
    """Повертає людиночитне пояснення, як пов’язані 'a' і 'b' (або повідомляє, що зв’язку нема)."""
    a_norm, b_norm = normalize_id(a), normalize_id(b)
    # Застосувати псевдоніми (синоніми) якщо присутні
    a_norm = ALIASES.get(a_norm, a_norm)
    b_norm = ALIASES.get(b_norm, b_norm)
    path = find_labeled_path(a_norm, b_norm)
    if not path:
        return f'Чи "{a_norm}" пов’язана з "{b_norm}"? — Хиба.'
    # Формуємо ланцюжок та кроки
    nodes = [node for node, _ in path]
    chain = " → ".join(nodes)
    steps: List[str] = []
    for i in range(len(path) - 1):
        node, edge_label = path[i]
        next_node = path[i + 1][0]
        steps.append(f"  {i+1}) {node} -({LABELS_UA.get(edge_label, edge_label)})-> {next_node}")
    return (
        f'Чи "{a_norm}" пов’язана з "{b_norm}"? — Істина.\n'
        f'Шлях: {chain}\nКроки:\n' + "\n".join(steps)
    )

# Транзитивні перевірки для конкретних відношень

def is_part_of_transitive(part: str, whole: str) -> bool:
    """True, якщо через відношення part_of (прямо чи опосередковано) `part` є частиною `whole`."""
    part_norm, whole_norm = normalize_id(part), normalize_id(whole)
    visited: Set[str] = {part_norm}
    queue: deque[str] = deque([part_norm])
    while queue:
        current = queue.popleft()
        if current == whole_norm:
            return True
        for p, w in PART_OF_EDGES:
            if p == current and w not in visited:
                visited.add(w)
                queue.append(w)
    return False

def has_part_transitive(whole: str, part: str) -> bool:
    """True, якщо `whole` (ціле) містить (прямо чи опосередковано) `part` як свою частину."""
    whole_norm, part_norm = normalize_id(whole), normalize_id(part)
    visited: Set[str] = {whole_norm}
    queue: deque[str] = deque([whole_norm])
    while queue:
        current = queue.popleft()
        if current == part_norm:
            return True
        for p, w in PART_OF_EDGES:
            if w == current and p not in visited:
                visited.add(p)
                queue.append(p)
    return False

def is_belongs_to_direct(dish: str, cuisine: str) -> bool:
    """True, якщо `dish` безпосередньо має відношення belongs_to з `cuisine`."""
    dish_norm = normalize_id(dish)
    cuisine_norm = ALIASES.get(normalize_id(cuisine), normalize_id(cuisine))
    return (dish_norm, cuisine_norm) in BELONGS_TO_EDGES

# 5) ПЕРЕВІРКА ВИМОГ (для самоконтролю)
def _max_depth_from(node: str) -> int:
    """Обчислює максимальну глибину дерева is_a, починаючи від вузла `node`."""
    return 1 + max((_max_depth_from(child) for child in ISA_CHILDREN_INDEX.get(node, [])), default=0)

def get_requirements_report() -> str:
    """Повертає звіт щодо виконання вимог (кількість класів, відношень, глибина ієрархії, інстанси)."""
    classes: Set[str] = {c for c, p in IS_A_EDGES} | {p for c, p in IS_A_EDGES}
    depth = max(_max_depth_from("сутність"), _max_depth_from("їжа"))
    # Перевірка: чи у кожного листового класу (в розділі "їжа") є >=2 інстансів
    missing_instances: List[str] = []
    for leaf in get_practical_leaf_classes():
        count = sum(1 for inst_class in INSTANCES.values() if inst_class == leaf)
        if count < 2:
            missing_instances.append(f"{leaf} ({count} інстанс)")
    inst_status = "OK" if not missing_instances else "нестача інстансів для: " + ", ".join(missing_instances)
    return (
        f"К-ть класів: {len(classes)} (має бути рівно 20)\n"
        f"Відношення: is_a={len(IS_A_EDGES)}, part_of={len(PART_OF_EDGES)}, belongs_to={len(BELONGS_TO_EDGES)} (мають існувати всі 3)\n"
        f"Глибина is_a: {depth} (має бути ≥4)\n"
        f"Інстанси листових: {inst_status}"
    )

# 6) ПАРСЕР ГІПОТЕЗ (розпізнавання тверджень українською мовою)
ALIASES: Dict[str, str] = {
    "живий": "організм", "жива": "організм", "живою": "організм",  # синоніми для прикладу "є живою" -> організм
    "їстівний": "їжа", "їстівна": "їжа", "їстівне": "їжа", "їстівною": "їжа",  # "є їстівною" -> їжа
    "італійської_кухні": "італійська_кухня",
    "української_кухні": "українська_кухня",
    "французької_кухні": "французька_кухня",
}

def evaluate_hypothesis(text: str) -> str:
    """Аналізує твердження українською мовою та перевіряє, чи воно істинне відповідно до онтології."""
    t = text.strip()
    patterns = [
        (r'^\s*(.+?)\s+є\s+частиною\s+(.+?)\s*$', "part_of"),
        (r'^\s*(.+?)\s+частина\s+(.+?)\s*$', "part_of"),
        (r'^\s*(.+?)\s+має\s+частину\s+(.+?)\s*$', "has_part"),
        (r'^\s*у\s+(.+?)\s+є\s+(.+?)\s*$', "has_part"),
        (r'^\s*(.+?)\s+належить\s+до\s+(.+? кухні)\s*$', "belongs_to"),
        (r'^\s*(.+?)\s+походить\s+з\s+(.+? кухні)\s*$', "belongs_to"),
        (r'^\s*(.+?)\s+є\s+(.+?)\s*$', "is_a"),
    ]
    for pattern, kind in patterns:
        match = re.match(pattern, t, flags=re.IGNORECASE)
        if not match:
            continue
        a_raw, b_raw = match.groups()
        if kind == "part_of":
            ok = is_part_of_transitive(a_raw, b_raw)
            return (f'Гіпотеза: "{a_raw} є частиною {b_raw}" → ' +
                    ("Істина\n\n" + explain_relationship(a_raw, b_raw) if ok else "Хиба"))
        if kind == "has_part":
            ok = has_part_transitive(a_raw, b_raw)
            return (f'Гіпотеза: "{a_raw} має частину {b_raw}" → ' +
                    ("Істина\n\n" + explain_relationship(a_raw, b_raw) if ok else "Хиба"))
        if kind == "belongs_to":
            ok = is_belongs_to_direct(a_raw, b_raw)
            # Зберігаємо формулювання користувача (належить до / походить з)
            verb = "належить до" if "належить до" in t.lower() else "походить з"
            # Додати слово "кухні" в кінці, якщо воно не було захоплене у b_raw (для коректності виводу)
            suffix = "" if b_raw.strip().endswith("кухні") else " кухні"
            return (f'Гіпотеза: "{a_raw} {verb} {b_raw}{suffix}" → ' +
                    ("Істина\n\n" + explain_relationship(a_raw, b_raw) if ok else "Хиба"))
        if kind == "is_a":
            a_norm = normalize_id(a_raw)
            b_norm = normalize_id(b_raw)
            b_norm = ALIASES.get(b_norm, b_norm)        # інтерпретація псевдонімів (якщо, наприклад, "їстівною" → "їжа")
            a_class = INSTANCES.get(a_norm, a_norm)     # якщо A – інстанс, беремо відповідний клас
            ok = (a_norm == b_norm) or is_subclass_of(a_norm, b_norm) or is_subclass_of(a_class, b_norm)
            return (f'Гіпотеза: "{a_raw} є {b_raw}" → ' +
                    ("Істина\n\n" + explain_relationship(a_raw, b_raw) if ok else "Хиба"))
    # Якщо жоден шаблон не підійшов:
    return ("Не розпізнав гіпотезу. Приклади:\n"
            "  томат є овоч\n"
            "  морква частина борщ\n"
            "  піца має частину сир\n"
            "  піца належить до італійської кухні\n"
            "  піца є їстівною")

# 7) GUI (інтерфейс для введення гіпотез та перевірки)
class OntologyApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Онтологія 'Кулінарія' — гіпотези та зв’язки")
        self.geometry("860x560")
        self.minsize(760, 480)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        # Вкладка "Гіпотеза (текст)"
        self.tab_hypothesis = ttk.Frame(notebook)
        notebook.add(self.tab_hypothesis, text="Гіпотеза (текст)")
        ttk.Label(
            self.tab_hypothesis,
            text=("Введіть гіпотезу українською (напр.:  томат є овоч / "
                  "морква частина борщ / піца має частину сир / "
                  "піца належить до італійської кухні / піца є їстівною):")
        ).pack(anchor="w", padx=8, pady=(8, 4))
        self.hypothesis_entry = ttk.Entry(self.tab_hypothesis)
        self.hypothesis_entry.pack(fill="x", padx=8, pady=4)
        self.hypothesis_entry.bind("<Return>", lambda e: self.on_check_hypothesis())
        ttk.Button(self.tab_hypothesis, text="Перевірити", command=self.on_check_hypothesis) \
            .pack(anchor="w", padx=8, pady=(4, 8))
        self.hypothesis_output = tk.Text(self.tab_hypothesis, height=18, wrap="word")
        self.hypothesis_output.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Вкладка "Відношення (ручна перевірка)"
        self.tab_relations = ttk.Frame(notebook)
        notebook.add(self.tab_relations, text="Відношення (ручна перевірка)")
        form = ttk.Frame(self.tab_relations)
        form.pack(fill="x", padx=8, pady=8)
        ttk.Label(form, text="A:").grid(row=0, column=0, sticky="w")
        self.input_a = ttk.Entry(form, width=30); self.input_a.grid(row=0, column=1, padx=4, pady=2)
        ttk.Label(form, text="B:").grid(row=0, column=2, sticky="w")
        self.input_b = ttk.Entry(form, width=30); self.input_b.grid(row=0, column=3, padx=4, pady=2)
        ttk.Button(form, text="Пояснити (будь-який зв’язок)", command=self.on_explain) \
            .grid(row=0, column=4, padx=6)
        ttk.Button(form, text="Перевірити is_a(A,B)", command=self.on_check_isa) \
            .grid(row=1, column=1, sticky="ew", padx=4, pady=4)
        ttk.Button(form, text="A є частиною B", command=self.on_check_partof) \
            .grid(row=1, column=2, sticky="ew", padx=4, pady=4)
        ttk.Button(form, text="A має частину B", command=self.on_check_haspart) \
            .grid(row=1, column=3, sticky="ew", padx=4, pady=4)
        ttk.Button(form, text="A належить до/з B кухні", command=self.on_check_belongs) \
            .grid(row=1, column=4, sticky="ew", padx=6, pady=4)
        self.relations_output = tk.Text(self.tab_relations, height=18, wrap="word")
        self.relations_output.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Вкладка "Перевірка вимог"
        self.tab_requirements = ttk.Frame(notebook)
        notebook.add(self.tab_requirements, text="Перевірка вимог")
        ttk.Button(self.tab_requirements, text="Перевірити вимоги", command=self.on_requirements) \
            .pack(anchor="w", padx=8, pady=8)
        self.requirements_output = tk.Text(self.tab_requirements, height=18, wrap="word")
        self.requirements_output.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # Обробники подій GUI:
    def on_check_hypothesis(self) -> None:
        text = self.hypothesis_entry.get().strip()
        if not text:
            messagebox.showinfo("Підказка", "Введіть гіпотезу, напр.:  томат є овоч")
            return
        self.hypothesis_output.delete("1.0", "end")
        self.hypothesis_output.insert("1.0", evaluate_hypothesis(text))

    def on_explain(self) -> None:
        a = self.input_a.get().strip()
        b = self.input_b.get().strip()
        if not a or not b:
            messagebox.showinfo("Підказка", "Заповніть поля A і B.")
            return
        self.relations_output.delete("1.0", "end")
        self.relations_output.insert("1.0", explain_relationship(a, b))

    def on_check_isa(self) -> None:
        a = normalize_id(self.input_a.get())
        b = normalize_id(self.input_b.get())
        a_class = INSTANCES.get(a, a)  # якщо A — інстанс, беремо його клас
        ok = (a == b) or is_subclass_of(a, b) or is_subclass_of(a_class, b)
        msg = f'Гіпотеза: "{a} є {b}" → ' + ("Істина\n\n" + explain_relationship(a, b) if ok else "Хиба")
        self.relations_output.delete("1.0", "end")
        self.relations_output.insert("1.0", msg)

    def on_check_partof(self) -> None:
        a = self.input_a.get()
        b = self.input_b.get()
        ok = is_part_of_transitive(a, b)
        msg = f'Гіпотеза: "{a} є частиною {b}" → ' + ("Істина\n\n" + explain_relationship(a, b) if ok else "Хиба")
        self.relations_output.delete("1.0", "end")
        self.relations_output.insert("1.0", msg)

    def on_check_haspart(self) -> None:
        a = self.input_a.get()
        b = self.input_b.get()
        ok = has_part_transitive(a, b)
        msg = f'Гіпотеза: "{a} має частину {b}" → ' + ("Істина\n\n" + explain_relationship(a, b) if ok else "Хиба")
        self.relations_output.delete("1.0", "end")
        self.relations_output.insert("1.0", msg)

    def on_check_belongs(self) -> None:
        a = self.input_a.get()
        b = self.input_b.get()
        ok = is_belongs_to_direct(a, b)
        msg = f'Гіпотеза: "{a} належить до {b}" → ' + ("Істина\n\n" + explain_relationship(a, b) if ok else "Хиба")
        self.relations_output.delete("1.0", "end")
        self.relations_output.insert("1.0", msg)

    def on_requirements(self) -> None:
        self.requirements_output.delete("1.0", "end")
        self.requirements_output.insert("1.0", get_requirements_report())

# 8) Точка входу
if __name__ == "__main__":
    OntologyApp().mainloop()

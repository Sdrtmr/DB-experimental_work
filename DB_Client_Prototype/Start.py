"""
================================================================================
ТЕХНИЧЕСКОЕ ЗАДАНИЕ: ОБЕСПЕЧЕНИЕ ЗАЩИТЫ БД И КОНТРОЛЬ ЦЕЛОСТНОСТИ ИНФОРМАЦИИ
================================================================================
Полнофункциональное приложение с графическим интерфейсом (tkinter).
Реализовано на SQLite с эмуляцией серверной СУБД (роли, пользователи, привилегии).

✔ Автоматическое создание/восстановление БД «Управление проектами» (4 таблицы + аудит)
✔ Аутентификация: admin, manager, employee (4 пользователя)
✔ Разграничение доступа (SELECT/INSERT/UPDATE/DELETE) в зависимости от роли
✔ Триггеры SQLite для аудита и контроля целостности
✔ Резервное копирование и восстановление
✔ Просмотр логов аудита
✔ Документированная политика безопасности
✔ Тестирование механизмов защиты в реальном времени

Запуск: python Start.py
================================================================================
"""

import sqlite3
import os
import shutil
from datetime import datetime
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox

# ==============================================================================
# 1. ЭМУЛЯТОР СЕРВЕРНОЙ БЕЗОПАСНОСТИ (ПОЛЬЗОВАТЕЛИ, РОЛИ, ПРИВИЛЕГИИ)
# ==============================================================================
class SecurityManager:
    """Полная эмуляция подсистемы безопасности серверной СУБД."""
    def __init__(self):
        self.users = {}          # login -> {'password_hash': str, 'role': str}
        self.roles = {}          # role -> set of privileges
        self.current_user = None # текущий аутентифицированный пользователь

    def create_user(self, login, password, role):
        """CREATE USER."""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.users[login] = {'password_hash': password_hash, 'role': role}

    def authenticate(self, login, password):
        """Проверка учётных данных."""
        if login not in self.users:
            return False
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return self.users[login]['password_hash'] == password_hash

    def set_current_user(self, login):
        """Установка текущего пользователя (сессия)."""
        if login in self.users:
            self.current_user = login
            return True
        return False

    def get_current_role(self):
        """Роль текущего пользователя."""
        if self.current_user:
            return self.users[self.current_user]['role']
        return None

    def grant_privilege(self, role, table, operation):
        """GRANT привилегии роли."""
        if role not in self.roles:
            self.roles[role] = set()
        self.roles[role].add((table, operation))

    def check_privilege(self, table, operation):
        """Проверка, разрешена ли операция текущему пользователю."""
        if not self.current_user:
            return False
        role = self.users[self.current_user]['role']
        if role == 'admin':   # администратор имеет все права
            return True
        if role not in self.roles:
            return False
        privs = self.roles[role]
        if ('*', operation) in privs or ('*', '*') in privs:
            return True
        return (table, operation) in privs


# Глобальный экземпляр менеджера безопасности
sec = SecurityManager()

# ==============================================================================
# 2. КОНСТАНТЫ И ПАРАМЕТРЫ
# ==============================================================================
DB_FILE = "ProjectManagement.db"
BACKUP_DIR = "backups"
os.makedirs(BACKUP_DIR, exist_ok=True)


# ==============================================================================
# 3. ФУНКЦИИ РАБОТЫ С БАЗОЙ ДАННЫХ (С ПРОВЕРКОЙ ПРАВ)
# ==============================================================================
def get_connection():
    """Создание соединения с БД."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def set_session_user(conn, username):
    """Устанавливает текущего пользователя в сессии БД (для триггеров)."""
    conn.execute("DELETE FROM session;")
    conn.execute("INSERT INTO session (id, current_user) VALUES (1, ?);", (username,))
    conn.commit()

def execute_query(conn, sql, params=(), table=None, operation=None, skip_privilege_check=False):
    """
    Выполняет SQL-запрос с предварительной проверкой прав.
    Если skip_privilege_check=True, проверка пропускается (для инициализации).
    Если table и operation указаны – проверяет привилегию.
    Возвращает курсор.
    """
    if not skip_privilege_check and table and operation:
        if not sec.check_privilege(table, operation):
            raise PermissionError(
                f"Access denied: user '{sec.current_user}' cannot {operation} on table '{table}'"
            )
    cursor = conn.cursor()
    cursor.execute(sql, params)
    conn.commit()
    return cursor

def init_database():
    """Надёжное создание БД: если файла нет ИЛИ он не содержит таблиц – создаёт заново."""
    # Проверяем, существует ли файл и есть ли в нём таблицы
    db_ok = False
    if os.path.exists(DB_FILE):
        try:
            conn = sqlite3.connect(DB_FILE)
            # Проверяем наличие хотя бы одной основной таблицы
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='employees';")
            if cur.fetchone():
                db_ok = True
            conn.close()
        except sqlite3.Error:
            db_ok = False

    # Если БД нет или она повреждена – удаляем старый файл и создаём заново
    if not db_ok:
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
        print("Создание новой базы данных ProjectManagement.db...")
    else:
        print("База данных уже существует и содержит таблицы. Пропускаем инициализацию.")
        return

    conn = get_connection()
    
    # ----- Таблицы данных -----
    execute_query(conn, """
    CREATE TABLE employees (
        employee_id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        position TEXT,
        hire_date DATE NOT NULL,
        mysql_user TEXT
    );
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TABLE projects (
        project_id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_name TEXT NOT NULL,
        start_date DATE,
        end_date DATE,
        status TEXT CHECK (status IN ('active', 'completed', 'onhold')) DEFAULT 'active'
    );
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TABLE tasks (
        task_id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        task_name TEXT NOT NULL,
        description TEXT,
        deadline DATE,
        status TEXT CHECK (status IN ('new', 'in_progress', 'done')) DEFAULT 'new',
        FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
    );
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TABLE assignments (
        assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        employee_id INTEGER NOT NULL,
        assigned_date DATE NOT NULL,
        hours_estimated DECIMAL(5,2),
        FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
        FOREIGN KEY (employee_id) REFERENCES employees(employee_id) ON DELETE CASCADE,
        CHECK (hours_estimated > 0)
    );
    """, skip_privilege_check=True)
    
    # ----- Таблицы аудита -----
    execute_query(conn, """
    CREATE TABLE audit_log (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        table_name TEXT NOT NULL,
        operation TEXT NOT NULL,
        old_data TEXT,
        new_data TEXT,
        changed_by TEXT NOT NULL,
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    CREATE TABLE task_status_history (
        history_id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        old_status TEXT,
        new_status TEXT,
        changed_by TEXT,
        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
    );
    """, skip_privilege_check=True)
    
    # ----- Таблица сессии (не временная!) -----
    execute_query(conn, """
    CREATE TABLE IF NOT EXISTS session (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        current_user TEXT NOT NULL
    );
    """, skip_privilege_check=True)
    execute_query(conn, "INSERT OR IGNORE INTO session (id, current_user) VALUES (1, 'system');", skip_privilege_check=True)
    
    # ----- Триггеры -----
    # 1. Аудит INSERT на tasks
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_after_insert
    AFTER INSERT ON tasks
    BEGIN
        INSERT INTO audit_log (table_name, operation, new_data, changed_by)
        VALUES ('tasks', 'INSERT',
                json_object('task_id', NEW.task_id, 'task_name', NEW.task_name, 'status', NEW.status),
                (SELECT current_user FROM session WHERE id = 1));
    END;
    """, skip_privilege_check=True)
    
    # 2. Аудит UPDATE на tasks
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_after_update
    AFTER UPDATE ON tasks
    BEGIN
        INSERT INTO audit_log (table_name, operation, old_data, new_data, changed_by)
        VALUES ('tasks', 'UPDATE',
                json_object('task_id', OLD.task_id, 'task_name', OLD.task_name, 'status', OLD.status),
                json_object('task_id', NEW.task_id, 'task_name', NEW.task_name, 'status', NEW.status),
                (SELECT current_user FROM session WHERE id = 1));
    END;
    """, skip_privilege_check=True)
    
    # 3. Аудит DELETE на tasks
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_after_delete
    AFTER DELETE ON tasks
    BEGIN
        INSERT INTO audit_log (table_name, operation, old_data, changed_by)
        VALUES ('tasks', 'DELETE',
                json_object('task_id', OLD.task_id, 'task_name', OLD.task_name, 'status', OLD.status),
                (SELECT current_user FROM session WHERE id = 1));
    END;
    """, skip_privilege_check=True)
    
    # 4. Контроль целостности: запрет завершения проекта с незавершёнными задачами
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS projects_before_update
    BEFORE UPDATE ON projects
    WHEN NEW.status = 'completed' AND OLD.status != 'completed'
    BEGIN
        SELECT RAISE(ABORT, 'Cannot complete project: there are unfinished tasks')
        WHERE EXISTS (SELECT 1 FROM tasks WHERE project_id = NEW.project_id AND status != 'done');
    END;
    """, skip_privilege_check=True)
    
    # 5. Журнал изменения статуса задач
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_status_update
    AFTER UPDATE ON tasks
    WHEN OLD.status != NEW.status
    BEGIN
        INSERT INTO task_status_history (task_id, old_status, new_status, changed_by)
        VALUES (NEW.task_id, OLD.status, NEW.status, (SELECT current_user FROM session WHERE id = 1));
    END;
    """, skip_privilege_check=True)
    
    # 6. Ограничение: сотрудник может назначать только себя
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS assignments_before_insert
    BEFORE INSERT ON assignments
    BEGIN
        SELECT RAISE(ABORT, 'Employees can only assign tasks to themselves')
        WHERE NOT EXISTS (
            SELECT 1 FROM employees 
            WHERE employee_id = NEW.employee_id 
            AND mysql_user = (SELECT current_user FROM session WHERE id = 1)
        )
        AND (SELECT current_user FROM session WHERE id = 1) NOT IN ('alex_admin', 'maria_manager');
    END;
    """, skip_privilege_check=True)
    
    # 7. Ограничение: сотрудник может изменять только свои назначения
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS assignments_before_update
    BEFORE UPDATE ON assignments
    BEGIN
        SELECT RAISE(ABORT, 'Employees can only update their own assignments')
        WHERE NOT EXISTS (
            SELECT 1 FROM employees 
            WHERE employee_id = NEW.employee_id 
            AND mysql_user = (SELECT current_user FROM session WHERE id = 1)
        )
        AND (SELECT current_user FROM session WHERE id = 1) NOT IN ('alex_admin', 'maria_manager');
    END;
    """, skip_privilege_check=True)
    
    # 8. Контроль целостности: дата приёма на работу не может быть в будущем
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS employees_before_insert_update
    BEFORE INSERT ON employees
    BEGIN
        SELECT RAISE(ABORT, 'Hire date cannot be in the future')
        WHERE NEW.hire_date > date('now');
    END;
    """, skip_privilege_check=True)
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS employees_before_update
    BEFORE UPDATE ON employees
    BEGIN
        SELECT RAISE(ABORT, 'Hire date cannot be in the future')
        WHERE NEW.hire_date > date('now');
    END;
    """, skip_privilege_check=True)
    
    # 9. Контроль целостности: дедлайн задачи не может быть в прошлом (при создании и обновлении)
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_before_insert_update
    BEFORE INSERT ON tasks
    BEGIN
        SELECT RAISE(ABORT, 'Deadline cannot be in the past')
        WHERE NEW.deadline IS NOT NULL AND NEW.deadline < date('now');
    END;
    """, skip_privilege_check=True)
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS tasks_before_update
    BEFORE UPDATE ON tasks
    BEGIN
        SELECT RAISE(ABORT, 'Deadline cannot be in the past')
        WHERE NEW.deadline IS NOT NULL AND NEW.deadline < date('now');
    END;
    """, skip_privilege_check=True)
    
    # 10. Контроль целостности: дата назначения не может быть в будущем
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS assignments_before_insert_update
    BEFORE INSERT ON assignments
    BEGIN
        SELECT RAISE(ABORT, 'Assigned date cannot be in the future')
        WHERE NEW.assigned_date > date('now');
    END;
    """, skip_privilege_check=True)
    execute_query(conn, """
    CREATE TRIGGER IF NOT EXISTS assignments_before_update_date
    BEFORE UPDATE ON assignments
    BEGIN
        SELECT RAISE(ABORT, 'Assigned date cannot be in the future')
        WHERE NEW.assigned_date > date('now');
    END;
    """, skip_privilege_check=True)
    
    # ----- Наполнение тестовыми данными -----
    execute_query(conn, """
    INSERT INTO employees (full_name, email, position, hire_date, mysql_user) VALUES
    ('Иван Петров', 'ivan.petrov@example.com', 'Разработчик', '2023-01-15', 'ivan_employee'),
    ('Елена Смирнова', 'elena.smirnova@example.com', 'Тестировщик', '2023-03-20', 'elena_employee'),
    ('Алексей Иванов', 'alex.ivanov@example.com', 'Менеджер', '2022-11-01', NULL);
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    INSERT INTO projects (project_name, start_date, status) VALUES
    ('Разработка CRM', '2025-01-10', 'active'),
    ('Мобильное приложение', '2025-02-01', 'active');
    """, skip_privilege_check=True)
    
    execute_query(conn, """
    INSERT INTO tasks (project_id, task_name, deadline, status) VALUES
    (1, 'Проектирование БД', '2026-03-01', 'done'),
    (1, 'Разработка API', '2026-04-01', 'in_progress'),
    (2, 'Дизайн интерфейса', '2026-03-15', 'new');
    """, skip_privilege_check=True)
    
    # --- Временно устанавливаем сессию администратора для вставки назначений ---
    execute_query(conn, "UPDATE session SET current_user = 'alex_admin' WHERE id = 1;", skip_privilege_check=True)
    
    execute_query(conn, """
    INSERT INTO assignments (task_id, employee_id, assigned_date, hours_estimated) VALUES
    (1, 1, '2025-01-20', 40.0),
    (2, 1, '2025-02-10', 80.0),
    (3, 2, '2025-02-15', 30.0);
    """, skip_privilege_check=True)
    
    conn.close()
    print("✓ База данных успешно создана и наполнена тестовыми данными.")


def setup_security_policy():
    """Инициализация ролей, пользователей и привилегий в эмуляторе."""
    # Привилегии менеджера
    tables = ['projects', 'tasks', 'employees', 'assignments']
    for tbl in tables:
        sec.grant_privilege('manager', tbl, 'SELECT')
        sec.grant_privilege('manager', tbl, 'INSERT')
        sec.grant_privilege('manager', tbl, 'UPDATE')
    # Менеджер может удалять только назначения
    sec.grant_privilege('manager', 'assignments', 'DELETE')
    
    # Привилегии сотрудника
    sec.grant_privilege('employee', 'tasks', 'SELECT')
    sec.grant_privilege('employee', 'projects', 'SELECT')
    sec.grant_privilege('employee', 'assignments', 'SELECT')
    sec.grant_privilege('employee', 'employees', 'SELECT')
    sec.grant_privilege('employee', 'assignments', 'INSERT')
    sec.grant_privilege('employee', 'assignments', 'UPDATE')
    # DELETE у сотрудника нет
    
    # Создание пользователей
    sec.create_user('alex_admin', 'SecurePass123', 'admin')
    sec.create_user('maria_manager', 'ManagerPass456', 'manager')
    sec.create_user('ivan_employee', 'EmployeePass789', 'employee')
    sec.create_user('elena_employee', 'EmployeePass000', 'employee')


def get_employee_id_by_user(username):
    """Возвращает employee_id для заданного mysql_user или None."""
    conn = get_connection()
    cur = conn.execute("SELECT employee_id FROM employees WHERE mysql_user = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row['employee_id'] if row else None


# ==============================================================================
# 4. РЕЗЕРВНОЕ КОПИРОВАНИЕ И ВОССТАНОВЛЕНИЕ
# ==============================================================================
def backup_database():
    """Создание резервной копии файла БД."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = os.path.join(BACKUP_DIR, f'ProjectManagement_backup_{timestamp}.db')
    shutil.copy2(DB_FILE, backup_file)
    return backup_file

def list_backups():
    """Возвращает список файлов резервных копий."""
    files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.db')]
    files.sort(reverse=True)
    return files

def restore_database(backup_filename):
    """Восстановление БД из резервной копии."""
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    if os.path.exists(backup_path):
        shutil.copy2(backup_path, DB_FILE)
        return True
    return False


# ==============================================================================
# 5. ГРАФИЧЕСКИЙ ИНТЕРФЕЙС
# ==============================================================================
class LoginWindow(tk.Toplevel):
    """Окно аутентификации с отображением паролей."""
    def __init__(self, master, on_success):
        super().__init__(master)
        self.title("Вход в систему безопасности БД")
        self.geometry("350x300")  # увеличено для отображения паролей
        self.resizable(False, False)
        self.on_success = on_success
        
        frame = ttk.Frame(self, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Аутентификация", font=('Arial', 14)).grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="Пользователь:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.user_var = tk.StringVar()
        self.user_combo = ttk.Combobox(frame, textvariable=self.user_var, state='readonly')
        self.user_combo['values'] = ('alex_admin', 'maria_manager', 'ivan_employee', 'elena_employee')
        self.user_combo.current(0)
        self.user_combo.grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="Пароль:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(frame, textvariable=self.pass_var, show='*')
        self.pass_entry.grid(row=2, column=1, pady=5)
        
        self.btn_login = ttk.Button(frame, text="Войти", command=self.login)
        self.btn_login.grid(row=3, column=0, columnspan=2, pady=10)
        
        # ---------- Панель с информацией об учётных записях ----------
        info_frame = ttk.Frame(frame)
        info_frame.grid(row=4, column=0, columnspan=2, pady=10, sticky=tk.W)
        info_text = (
            "Учётные записи:\n"
            "────────────────\n"
            "alex_admin    / SecurePass123\n"
            "maria_manager / ManagerPass456\n"
            "ivan_employee / EmployeePass789\n"
            "elena_employee / EmployeePass000"
        )
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT, font=('Consolas', 9)).pack()
        
        self.bind('<Return>', lambda e: self.login())
        self.pass_entry.focus()
        
    def login(self):
        username = self.user_var.get()
        password = self.pass_var.get()
        if sec.authenticate(username, password):
            sec.set_current_user(username)
            self.destroy()
            self.on_success(username)
        else:
            messagebox.showerror("Ошибка", "Неверный логин или пароль")
            self.pass_var.set("")


class MainWindow(tk.Tk):
    """Главное окно приложения."""
    def __init__(self):
        super().__init__()
        self.title("Система защиты БД «Управление проектами»")
        self.geometry("900x600")
        self.current_user = None
        self.current_employee_id = None
        
        # Инициализация БД и политик (выполняется однократно)
        init_database()
        setup_security_policy()
        
        # Запуск окна логина
        self.withdraw()
        LoginWindow(self, self.on_login_success)
        
    def on_login_success(self, username):
        """Колбэк после успешного входа."""
        self.current_user = username
        self.current_employee_id = get_employee_id_by_user(username)
        self.deiconify()
        self.create_widgets()
        self.refresh_table_list()
        
    def create_widgets(self):
        """Создание элементов интерфейса."""
        # Верхняя панель с информацией о пользователе
        top_frame = ttk.Frame(self, relief=tk.RAISED, padding=5)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        role = sec.get_current_role()
        ttk.Label(top_frame, text=f"Пользователь: {self.current_user} (роль: {role})",
                  font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        ttk.Button(top_frame, text="Сменить пользователя", 
                   command=self.logout).pack(side=tk.RIGHT, padx=5)
        ttk.Button(top_frame, text="Выход", command=self.quit_app).pack(side=tk.RIGHT, padx=5)
        
        # Основной контейнер с вкладками
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладка 1: Таблицы
        self.tab_tables = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_tables, text="Таблицы")
        self.setup_tables_tab()
        
        # Вкладка 2: Аудит
        self.tab_audit = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_audit, text="Аудит")
        self.setup_audit_tab()
        
        # Вкладка 3: Резервное копирование
        self.tab_backup = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_backup, text="Резервное копирование")
        self.setup_backup_tab()
        
        # Вкладка 4: Политика безопасности
        self.tab_policy = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_policy, text="Политика безопасности")
        self.setup_policy_tab()
        
        # Вкладка 5: Тестирование
        self.tab_test = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_test, text="Тестирование")
        self.setup_test_tab()
        
    # ---------- Вкладка "Таблицы" ----------
    def setup_tables_tab(self):
        """Настройка интерфейса для работы с таблицами."""
        frame = ttk.Frame(self.tab_tables, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Выбор таблицы
        ttk.Label(frame, text="Таблица:").grid(row=0, column=0, sticky=tk.W)
        self.table_var = tk.StringVar()
        self.table_combo = ttk.Combobox(frame, textvariable=self.table_var, state='readonly')
        self.table_combo['values'] = ('employees', 'projects', 'tasks', 'assignments')
        self.table_combo.current(0)
        self.table_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.table_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_table_view())
        
        # Кнопки управления
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=0, column=2, padx=20)
        
        self.btn_refresh = ttk.Button(btn_frame, text="Обновить", command=self.refresh_table_view)
        self.btn_refresh.pack(side=tk.LEFT, padx=2)
        
        self.btn_add = ttk.Button(btn_frame, text="Добавить", command=self.add_record)
        self.btn_add.pack(side=tk.LEFT, padx=2)
        
        self.btn_edit = ttk.Button(btn_frame, text="Изменить", command=self.edit_record)
        self.btn_edit.pack(side=tk.LEFT, padx=2)
        
        self.btn_delete = ttk.Button(btn_frame, text="Удалить", command=self.delete_record)
        self.btn_delete.pack(side=tk.LEFT, padx=2)
        
        # Область отображения данных
        tree_frame = ttk.Frame(frame)
        tree_frame.grid(row=1, column=0, columnspan=4, sticky=tk.NSEW, pady=10)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        
        # Вертикальный и горизонтальный скроллы
        v_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        h_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        self.tree = ttk.Treeview(tree_frame, 
                                 yscrollcommand=v_scroll.set,
                                 xscrollcommand=h_scroll.set,
                                 selectmode='browse')
        v_scroll.config(command=self.tree.yview)
        h_scroll.config(command=self.tree.xview)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Первоначальная загрузка
        self.refresh_table_list()
        
    def refresh_table_list(self):
        """Обновляет список доступных таблиц в зависимости от прав."""
        table = self.table_var.get()
        self.refresh_table_view()
        
    def refresh_table_view(self):
        """Загружает данные из выбранной таблицы в Treeview."""
        table = self.table_var.get()
        if not table:
            return
        
        # Очистка
        self.tree.delete(*self.tree.get_children())
        
        conn = get_connection()
        set_session_user(conn, self.current_user)
        
        try:
            # Для сотрудника ограничиваем просмотр assignments только его записями
            if table == 'assignments' and sec.get_current_role() == 'employee' and self.current_employee_id:
                cur = conn.execute(
                    "SELECT * FROM assignments WHERE employee_id = ?",
                    (self.current_employee_id,)
                )
            else:
                cur = conn.execute(f"SELECT * FROM {table} LIMIT 100")
            
            rows = cur.fetchall()
            if rows:
                # Устанавливаем колонки
                columns = list(rows[0].keys())
                self.tree['columns'] = columns
                self.tree['show'] = 'headings'
                for col in columns:
                    self.tree.heading(col, text=col)
                    self.tree.column(col, width=100, anchor=tk.CENTER)
                
                # Вставляем строки
                for row in rows:
                    values = [row[col] for col in columns]
                    self.tree.insert('', tk.END, values=values)
        except sqlite3.Error as e:
            messagebox.showerror("Ошибка БД", str(e))
        finally:
            conn.close()
        
        # Обновление состояния кнопок в зависимости от прав
        self.update_button_states()
    
    def update_button_states(self):
        """Включает/выключает кнопки в соответствии с привилегиями."""
        table = self.table_var.get()
        # Добавление
        if sec.check_privilege(table, 'INSERT'):
            self.btn_add.config(state=tk.NORMAL)
        else:
            self.btn_add.config(state=tk.DISABLED)
        # Изменение
        if sec.check_privilege(table, 'UPDATE'):
            self.btn_edit.config(state=tk.NORMAL)
        else:
            self.btn_edit.config(state=tk.DISABLED)
        # Удаление
        if sec.check_privilege(table, 'DELETE'):
            self.btn_delete.config(state=tk.NORMAL)
        else:
            self.btn_delete.config(state=tk.DISABLED)
    
    def get_selected_row(self):
        """Возвращает словарь с данными выделенной строки или None."""
        selection = self.tree.selection()
        if not selection:
            return None
        item = selection[0]
        values = self.tree.item(item, 'values')
        columns = self.tree['columns']
        return dict(zip(columns, values))
    
    def add_record(self):
        """Добавление новой записи."""
        table = self.table_var.get()
        if table == 'assignments' and sec.get_current_role() == 'employee':
            # Принудительно подставляем employee_id текущего сотрудника
            if not self.current_employee_id:
                messagebox.showerror("Ошибка", "Ваш профиль сотрудника не найден")
                return
            # Вызов диалога с предзаполненным employee_id
            self.show_add_edit_dialog(table, mode='add', default_emp_id=self.current_employee_id)
        else:
            self.show_add_edit_dialog(table, mode='add')
    
    def edit_record(self):
        """Изменение существующей записи."""
        table = self.table_var.get()
        row_data = self.get_selected_row()
        if not row_data:
            messagebox.showinfo("Информация", "Выберите запись для изменения")
            return
        self.show_add_edit_dialog(table, mode='edit', initial_data=row_data)
    
    def delete_record(self):
        """Удаление записи."""
        table = self.table_var.get()
        row_data = self.get_selected_row()
        if not row_data:
            messagebox.showinfo("Информация", "Выберите запись для удаления")
            return
        
        pk_column = {
            'employees': 'employee_id',
            'projects': 'project_id',
            'tasks': 'task_id',
            'assignments': 'assignment_id'
        }.get(table)
        
        if not pk_column or pk_column not in row_data:
            messagebox.showerror("Ошибка", "Не удалось определить первичный ключ")
            return
        
        pk_value = row_data[pk_column]
        
        if not messagebox.askyesno("Подтверждение", f"Удалить запись с {pk_column}={pk_value}?"):
            return
        
        conn = get_connection()
        set_session_user(conn, self.current_user)
        try:
            execute_query(conn, f"DELETE FROM {table} WHERE {pk_column} = ?",
                         (pk_value,), table=table, operation='DELETE')
            messagebox.showinfo("Успех", "Запись удалена")
            self.refresh_table_view()
        except (sqlite3.Error, PermissionError) as e:
            messagebox.showerror("Ошибка", str(e))
        finally:
            conn.close()
    
    def show_add_edit_dialog(self, table, mode='add', initial_data=None, default_emp_id=None):
        """Диалог для добавления/редактирования записи."""
        dialog = tk.Toplevel(self)
        dialog.title("Добавление записи" if mode == 'add' else "Редактирование записи")
        dialog.geometry("500x400")
        dialog.transient(self)
        dialog.grab_set()
        
        # Получаем информацию о колонках таблицы
        conn = get_connection()
        cur = conn.execute(f"PRAGMA table_info({table})")
        columns_info = cur.fetchall()
        conn.close()
        
        # Поля ввода
        entries = {}
        row_num = 0
        for col_info in columns_info:
            col_name = col_info[1]
            col_type = col_info[2]
            not_null = col_info[3]
            pk = col_info[5]
            
            # Пропускаем autoincrement первичные ключи при добавлении
            if mode == 'add' and pk and col_info[4] == 1:  # autoincrement
                continue
            
            ttk.Label(dialog, text=f"{col_name} ({col_type}):").grid(row=row_num, column=0, sticky=tk.W, padx=5, pady=2)
            
            var = tk.StringVar()
            # Предзаполнение для редактирования
            if initial_data and col_name in initial_data:
                var.set(initial_data[col_name])
            # Принудительное employee_id для сотрудника при добавлении назначения
            if mode == 'add' and table == 'assignments' and col_name == 'employee_id' and default_emp_id:
                var.set(str(default_emp_id))
                entry = ttk.Entry(dialog, textvariable=var, state='readonly')
            else:
                entry = ttk.Entry(dialog, textvariable=var)
            
            entry.grid(row=row_num, column=1, sticky=tk.W+tk.E, padx=5, pady=2)
            entries[col_name] = var
            row_num += 1
        
        def save():
            # Собираем значения
            cols = []
            placeholders = []
            values = []
            for col_name, var in entries.items():
                val = var.get().strip()
                if not val and not_null:
                    messagebox.showerror("Ошибка", f"Поле {col_name} обязательно")
                    return
                cols.append(col_name)
                placeholders.append('?')
                values.append(val)
            
            conn = get_connection()
            set_session_user(conn, self.current_user)
            try:
                if mode == 'add':
                    sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join(placeholders)})"
                    execute_query(conn, sql, values, table=table, operation='INSERT')
                else:
                    pk_column = {
                        'employees': 'employee_id',
                        'projects': 'project_id',
                        'tasks': 'task_id',
                        'assignments': 'assignment_id'
                    }.get(table)
                    if not pk_column:
                        raise ValueError("Неизвестный первичный ключ")
                    pk_value = initial_data[pk_column]
                    set_clause = ', '.join([f"{col} = ?" for col in cols])
                    sql = f"UPDATE {table} SET {set_clause} WHERE {pk_column} = ?"
                    values.append(pk_value)
                    execute_query(conn, sql, values, table=table, operation='UPDATE')
                
                conn.commit()
                messagebox.showinfo("Успех", "Данные сохранены")
                dialog.destroy()
                self.refresh_table_view()
            except (sqlite3.Error, PermissionError) as e:
                messagebox.showerror("Ошибка", str(e))
            finally:
                conn.close()
        
        ttk.Button(dialog, text="Сохранить", command=save).grid(row=row_num, column=0, pady=10)
        ttk.Button(dialog, text="Отмена", command=dialog.destroy).grid(row=row_num, column=1, pady=10)
        
        dialog.columnconfigure(1, weight=1)
    
    # ---------- Вкладка "Аудит" ----------
    def setup_audit_tab(self):
        """Просмотр логов аудита."""
        frame = ttk.Frame(self.tab_audit, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Таблица аудита:").pack(anchor=tk.W)
        self.audit_table_var = tk.StringVar(value='audit_log')
        audit_combo = ttk.Combobox(frame, textvariable=self.audit_table_var, state='readonly')
        audit_combo['values'] = ('audit_log', 'task_status_history')
        audit_combo.pack(anchor=tk.W, pady=5)
        audit_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_audit_view())
        
        ttk.Button(frame, text="Обновить", command=self.refresh_audit_view).pack(anchor=tk.W, pady=5)
        
        # Treeview для логов
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        v_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        h_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        self.audit_tree = ttk.Treeview(tree_frame,
                                       yscrollcommand=v_scroll.set,
                                       xscrollcommand=h_scroll.set)
        v_scroll.config(command=self.audit_tree.yview)
        h_scroll.config(command=self.audit_tree.xview)
        
        self.audit_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.refresh_audit_view()
    
    def refresh_audit_view(self):
        """Загружает данные из таблицы аудита."""
        table = self.audit_table_var.get()
        self.audit_tree.delete(*self.audit_tree.get_children())
        
        conn = get_connection()
        try:
            cur = conn.execute(f"SELECT * FROM {table} ORDER BY changed_at DESC LIMIT 200")
            rows = cur.fetchall()
            if rows:
                columns = list(rows[0].keys())
                self.audit_tree['columns'] = columns
                self.audit_tree['show'] = 'headings'
                for col in columns:
                    self.audit_tree.heading(col, text=col)
                    self.audit_tree.column(col, width=120)
                for row in rows:
                    values = [row[col] for col in columns]
                    self.audit_tree.insert('', tk.END, values=values)
        except sqlite3.Error as e:
            messagebox.showerror("Ошибка", str(e))
        finally:
            conn.close()
    
    # ---------- Вкладка "Резервное копирование" ----------
    def setup_backup_tab(self):
        """Интерфейс резервного копирования."""
        frame = ttk.Frame(self.tab_backup, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(frame, text="Создать резервную копию",
                   command=self.do_backup).pack(pady=5)
        
        ttk.Label(frame, text="Доступные копии:").pack(anchor=tk.W, pady=(10,0))
        
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        v_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        self.backup_listbox = tk.Listbox(list_frame, yscrollcommand=v_scroll.set)
        v_scroll.config(command=self.backup_listbox.yview)
        
        self.backup_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.refresh_backup_list()
        
        btn_restore = ttk.Button(frame, text="Восстановить из выбранной копии",
                                 command=self.do_restore)
        btn_restore.pack(pady=5)
    
    def refresh_backup_list(self):
        """Обновляет список бэкапов."""
        self.backup_listbox.delete(0, tk.END)
        for f in list_backups():
            self.backup_listbox.insert(tk.END, f)
    
    def do_backup(self):
        """Создание бэкапа."""
        try:
            file = backup_database()
            messagebox.showinfo("Успех", f"Резервная копия создана:\n{file}")
            self.refresh_backup_list()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
    
    def do_restore(self):
        """Восстановление из выбранной копии."""
        selection = self.backup_listbox.curselection()
        if not selection:
            messagebox.showinfo("Информация", "Выберите резервную копию")
            return
        filename = self.backup_listbox.get(selection[0])
        if messagebox.askyesno("Подтверждение", f"Восстановить БД из {filename}?"):
            if restore_database(filename):
                messagebox.showinfo("Успех", "Восстановление выполнено.\nПерезайдите в систему.")
                self.logout()
            else:
                messagebox.showerror("Ошибка", "Не удалось восстановить")
    
    # ---------- Вкладка "Политика безопасности" ----------
    def setup_policy_tab(self):
        """Отображение политики безопасности."""
        frame = ttk.Frame(self.tab_policy, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(frame, wrap=tk.WORD, font=('Consolas', 10))
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.config(yscrollcommand=scroll.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        policy_text = self.get_security_policy()
        text_widget.insert(tk.END, policy_text)
        text_widget.config(state=tk.DISABLED)
    
    def get_security_policy(self):
        """Возвращает текст политики безопасности."""
        return """
================================================================================
                         ПОЛИТИКА БЕЗОПАСНОСТИ БД
                     Проект: Управление проектами (ProjectManagement)
================================================================================

1. ЦЕЛИ
   - Обеспечение конфиденциальности, целостности и доступности данных.
   - Контроль изменений и аудит действий пользователей.
   - Разграничение доступа на основе ролевой модели.

2. СУБД
   - SQLite с эмуляцией серверной безопасности.
   - Файл базы данных: ProjectManagement.db.

3. РОЛИ И ПРИВИЛЕГИИ
   ------------------------------------------------------------------------
   Роль      | Таблицы        | SELECT | INSERT | UPDATE | DELETE
   ------------------------------------------------------------------------
   admin    | все             |   ✔    |   ✔    |   ✔    |   ✔
   manager  | projects        |   ✔    |   ✔    |   ✔    |   ✘
            | tasks           |   ✔    |   ✔    |   ✔    |   ✘
            | employees       |   ✔    |   ✔    |   ✔    |   ✘
            | assignments     |   ✔    |   ✔    |   ✔    |   ✔
   employee | tasks           |   ✔    |   ✘    |   ✘    |   ✘
            | projects        |   ✔    |   ✘    |   ✘    |   ✘
            | employees       |   ✔    |   ✘    |   ✘    |   ✘
            | assignments     |   ✔    |   ✔*   |   ✔*   |   ✘
            * только на свои записи (employee_id соответствует учётной записи)
   ------------------------------------------------------------------------

4. ПОЛЬЗОВАТЕЛИ
   - alex_admin    (пароль: SecurePass123)   – администратор
   - maria_manager (пароль: ManagerPass456)  – менеджер
   - ivan_employee (пароль: EmployeePass789) – сотрудник (разработчик)
   - elena_employee(пароль: EmployeePass000) – сотрудник (тестировщик)

5. КОНТРОЛЬ ЦЕЛОСТНОСТИ
   - Внешние ключи (FOREIGN KEY) – обеспечение ссылочной целостности.
   - Ограничения CHECK (положительные часы, статусы).
   - Триггеры для проверки дат (найм не в будущем, дедлайн не в прошлом, дата назначения не в будущем).
   - Триггер projects_before_update – запрещает завершение проекта с незакрытыми задачами.
   - Триггеры assignments_before_insert/update – ограничивают сотрудников их собственными назначениями.

6. АУДИТ
   - Таблица audit_log – журналирует все INSERT/UPDATE/DELETE по таблице tasks.
   - Таблица task_status_history – отслеживает изменения статуса задач.
   - Фиксируется: кто, когда, старые/новые данные (в JSON).

7. РЕЗЕРВНОЕ КОПИРОВАНИЕ
   - Копирование файла .db в папку backups/ с меткой времени.
   - Возможность восстановления из любой копии.

8. ОТВЕТСТВЕННЫЙ
   - Администратор БД: alex_admin.
   - Все изменения регистрируются в аудите.

================================================================================
        """
    
    # ---------- Вкладка "Тестирование" ----------
    def setup_test_tab(self):
        """Автоматизированное тестирование механизмов безопасности."""
        frame = ttk.Frame(self.tab_test, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Button(frame, text="Запустить полное тестирование",
                   command=self.run_tests).pack(pady=10)
        
        ttk.Label(frame, text="Результаты:").pack(anchor=tk.W)
        
        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL)
        self.test_output = tk.Text(text_frame, wrap=tk.WORD,
                                   yscrollcommand=scroll.set,
                                   font=('Consolas', 9))
        scroll.config(command=self.test_output.yview)
        
        self.test_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def run_tests(self):
        """Выполняет набор тестов и выводит результат."""
        self.test_output.delete(1.0, tk.END)
        self.test_output.insert(tk.END, "ЗАПУСК ТЕСТИРОВАНИЯ...\n")
        self.test_output.insert(tk.END, "="*60 + "\n")
        
        # Сохраняем текущего пользователя, чтобы потом восстановить
        original_user = sec.current_user
        
        def log(msg):
            self.test_output.insert(tk.END, msg + "\n")
            self.test_output.see(tk.END)
            self.update()
        
        try:
            # Тест 1: Администратор
            sec.set_current_user('alex_admin')
            conn = get_connection()
            set_session_user(conn, 'alex_admin')
            log("[ADMIN] Проверка DELETE...")
            execute_query(conn, "DELETE FROM assignments WHERE assignment_id = 999", 
                         table='assignments', operation='DELETE')
            log("  ✓ DELETE разрешён")
            conn.close()
            
            # Тест 2: Менеджер
            sec.set_current_user('maria_manager')
            conn = get_connection()
            set_session_user(conn, 'maria_manager')
            log("\n[MANAGER] Проверка DELETE на assignments...")
            execute_query(conn, "DELETE FROM assignments WHERE assignment_id = 1",
                         table='assignments', operation='DELETE')
            conn.rollback()
            log("  ✓ DELETE на assignments разрешён")
            
            log("[MANAGER] Проверка DELETE на projects (ожидается отказ)...")
            try:
                execute_query(conn, "DELETE FROM projects WHERE project_id = 1",
                             table='projects', operation='DELETE')
                log("  ✗ DELETE разрешён (ОШИБКА)")
            except PermissionError as e:
                log(f"  ✓ DELETE запрещён: {e}")
            conn.close()
            
            # Тест 3: Сотрудник
            sec.set_current_user('ivan_employee')
            conn = get_connection()
            set_session_user(conn, 'ivan_employee')
            log("\n[EMPLOYEE] Проверка INSERT на себя...")
            try:
                execute_query(conn, """
                    INSERT INTO assignments (task_id, employee_id, assigned_date, hours_estimated)
                    VALUES (2, 1, date('now'), 5.0)
                """, table='assignments', operation='INSERT')
                conn.rollback()
                log("  ✓ INSERT на себя разрешён")
            except sqlite3.Error as e:
                log(f"  ✗ INSERT запрещён: {e}")
            
            log("[EMPLOYEE] Проверка INSERT на другого сотрудника (ожидается отказ)...")
            try:
                execute_query(conn, """
                    INSERT INTO assignments (task_id, employee_id, assigned_date, hours_estimated)
                    VALUES (3, 2, date('now'), 5.0)
                """, table='assignments', operation='INSERT')
                conn.rollback()
                log("  ✗ INSERT на другого разрешён (ОШИБКА)")
            except sqlite3.DatabaseError as e:
                log(f"  ✓ INSERT запрещён триггером: {e}")
            
            log("[EMPLOYEE] Проверка DELETE (ожидается отказ)...")
            try:
                execute_query(conn, "DELETE FROM assignments WHERE assignment_id = 1",
                             table='assignments', operation='DELETE')
                log("  ✗ DELETE разрешён (ОШИБКА)")
            except PermissionError as e:
                log(f"  ✓ DELETE запрещён: {e}")
            conn.close()
            
            # Тест 4: Триггер контроля целостности
            sec.set_current_user('alex_admin')
            conn = get_connection()
            set_session_user(conn, 'alex_admin')
            log("\n[INTEGRITY] Попытка закрыть проект с незавершёнными задачами...")
            try:
                conn.execute("UPDATE projects SET status = 'completed' WHERE project_id = 1")
                conn.commit()
                log("  ✗ Проект закрыт (ОШИБКА)")
            except sqlite3.DatabaseError as e:
                log(f"  ✓ Триггер сработал: {e}")
            conn.close()
            
            # Тест 5: Аудит
            sec.set_current_user('alex_admin')
            conn = get_connection()
            set_session_user(conn, 'alex_admin')
            cur = conn.execute("SELECT COUNT(*) FROM audit_log")
            count = cur.fetchone()[0]
            log(f"\n[AUDIT] Записей в audit_log: {count}")
            cur = conn.execute("SELECT COUNT(*) FROM task_status_history")
            count = cur.fetchone()[0]
            log(f"[AUDIT] Записей в task_status_history: {count}")
            conn.close()
            
        except Exception as e:
            log(f"\n!!! Ошибка тестирования: {e}")
        finally:
            # Восстанавливаем исходного пользователя
            if original_user:
                sec.set_current_user(original_user)
            else:
                sec.set_current_user(None)
        
        log("\n" + "="*60)
        log("ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    
    # ---------- Вспомогательные методы ----------
    def logout(self):
        """Возврат к окну входа."""
        sec.set_current_user(None)
        self.current_user = None
        self.current_employee_id = None
        self.withdraw()
        LoginWindow(self, self.on_login_success)
    
    def quit_app(self):
        """Завершение приложения."""
        if messagebox.askyesno("Выход", "Завершить работу?"):
            self.quit()
            self.destroy()


# ==============================================================================
# 6. ЗАПУСК ПРИЛОЖЕНИЯ
# ==============================================================================
if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
# Directory Object Migrator - Architecture Document

## Оглавление
1. [Обзор](#обзор)
2. [Компоненты системы](#компоненты-системы)
3. [Поток данных](#поток-данных)
4. [База данных миграции](#база-данных-миграции)
5. [Обработка ссылочных атрибутов](#обработка-ссылочных-атрибутов)
6. [Идемпотентность](#идемпотентность)
7. [Обработка ошибок](#обработка-ошибок)

## Обзор

Directory Object Migrator — это инструмент для миграции объектов из Microsoft Active Directory в Samba AD через протокол LDAP.

### Ключевые принципы проектирования

1. **Безопасность**: Никогда не перезаписывать существующие объекты в destination
2. **Идемпотентность**: Повторные запуски безопасны и дополняют предыдущие
3. **Прозрачность**: Детальное логирование всех операций
4. **Поэтапность**: Миграция разбита на четкие фазы
5. **Tracking**: SQLite БД отслеживает соответствие объектов между доменами

## Компоненты системы

### 1. GUI Layer (PyQt5)

**Файлы**: `gui/`

#### MainWindow
- Главное окно приложения
- Навигация между шагами миграции
- Отображение логов в реальном времени

#### ConnectionDialog
- Настройка подключений к Source и Destination DC
- Тест подключения
- Валидация credentials

#### PreviewDialog
- Отображение результатов анализа
- Preview плана миграции (что будет создано/пропущено)
- Подтверждение перед началом миграции

#### ProgressWindow
- Индикатор прогресса выполнения
- Отображение текущей фазы
- Real-time лог операций
- Кнопка отмены

### 2. Core Layer

**Файлы**: `core/`

#### LDAPConnector
```python
class LDAPConnector:
    """Обертка над ldap3 для подключения к DC"""
    
    def connect(host, port, domain, username, password, use_tls)
    def search(base_dn, search_filter, attributes, scope)
    def add(dn, object_class, attributes)
    def modify(dn, changes)
    def delete(dn)
    def get_object_by_guid(guid)
    def get_object_by_dn(dn)
```

#### Analyzer
```python
class Analyzer:
    """Анализ source домена, классификация объектов"""
    
    def analyze(base_dn) -> AnalysisResult
    def classify_object(ldap_entry) -> ObjectType
    def build_dependency_tree(objects) -> DependencyTree
```

**Логика анализа:**
1. LDAP search с scope=SUBTREE от base_dn
2. Классификация по objectClass:
   - organizationalUnit → OU
   - user (NOT computer) → User
   - group → Group
   - contact → Contact
3. Проверка ignored patterns (Builtin, ForeignSecurityPrincipals)
4. Построение иерархии OU (по глубине DN)
5. Выявление ссылочных атрибутов (member, manager, managedBy)

#### Migrator
```python
class Migrator:
    """Главный движок миграции"""
    
    def __init__(source_conn, dest_conn, migration_db, config)
    def migrate(base_dn, options) -> MigrationResult
    def _phase1_create_ous(ou_list)
    def _phase2_create_objects(objects)
    def _phase3_copy_attributes(objects)
    def _phase4_resolve_references(objects)
    def _phase5_verify(objects)
```

**Последовательность фаз:**

**Phase 1: Create OUs**
- Сортировка OU по глубине (от корня к листьям)
- Создание через LDAP add
- Запись в migration_map

**Phase 2: Create Objects**
- Создание Users, Groups, Contacts
- Только базовые required атрибуты (cn, sAMAccountName)
- Пароли для users: random 12 chars
- userAccountControl: ACCOUNTDISABLE (0x0002)
- Запись в migration_map

**Phase 3: Copy Attributes**
- Чтение всех атрибутов из source
- Фильтрация по attribute_mappings.yaml
- Трансформация (UPN, email domain suffix)
- LDAP modify для destination объектов

**Phase 4: Resolve References**
- Обработка reference attributes (member, manager, managedBy)
- Для каждой ссылки:
  - Поиск в migration_map: есть ли target в destination?
  - ДА → установить атрибут
  - НЕТ → записать в deferred_references
- Для повторных запусков: проверка deferred_references, разрешение если target появился

**Phase 5: Verification**
- Подсчет объектов в source vs destination
- Проверка критичных атрибутов
- Проверка неразрешенных ссылок
- Генерация отчета

#### Object Handlers

**Файлы**: `core/object_handlers/`

Каждый тип объекта имеет свой handler:

```python
class ObjectHandler(ABC):
    @abstractmethod
    def create(source_entry, dest_conn) -> str  # returns dest_dn
    
    @abstractmethod
    def copy_attributes(source_entry, dest_entry, config)
    
    @abstractmethod
    def get_reference_attributes() -> List[str]
```

**OUHandler**
- Простейший: только description, managedBy

**UserHandler**
- Генерация пароля
- Установка userAccountControl
- Трансформация UPN/email
- primaryGroupID = 513

**GroupHandler**
- Сохранение groupType
- Обработка multi-valued member attribute
- DEFERRED для членов вне scope

**ContactHandler**
- Похож на User, но без пароля и UAC

#### AttributeMapper
```python
class AttributeMapper:
    """Маппинг и трансформация атрибутов"""
    
    def __init__(config_yaml)
    def should_copy_attribute(attr_name, object_type) -> bool
    def transform_attribute(attr_name, value, transform_rules) -> Any
```

**Трансформации:**
- **UPN**: `user@source.alt` → `user@dest.alt`
- **Email**: аналогично
- **proxyAddresses**: `SMTP:user@source.alt` → `SMTP:user@dest.alt`

#### ReferenceResolver
```python
class ReferenceResolver:
    """Разрешение ссылочных атрибутов"""
    
    def resolve_reference(source_dn, migration_db) -> Optional[str]
    def defer_reference(parent_guid, attr_name, ref_dn)
    def process_deferred_references() -> int  # returns count resolved
```

**Алгоритм:**
1. Извлечь referenced DN из атрибута
2. Поиск в `migration_map` по `source_dn`
3. Если найден → вернуть `dest_dn`
4. Если не найден → записать в `deferred_references`, вернуть None

#### Verifier
```python
class Verifier:
    """Верификация результатов миграции"""
    
    def verify(source_conn, dest_conn, migration_db, base_dn) -> VerificationResult
    def count_objects_by_type(conn, base_dn) -> Dict[str, int]
    def check_deferred_references(migration_db) -> List[DeferredRef]
```

### 3. Database Layer

**Файлы**: `database/`

#### MigrationDB
```python
class MigrationDB:
    """SQLite интерфейс для migration tracking"""
    
    def __init__(db_path)
    
    # Migration runs
    def create_migration_run(source_dn, dest_dn, config) -> int  # run_id
    def update_migration_run(run_id, stats, status)
    def get_latest_run() -> MigrationRun
    
    # Object mapping
    def add_object(source_guid, source_dn, dest_guid, dest_dn, obj_type, status, run_id)
    def get_object_by_source_guid(guid) -> Optional[MigrationMapEntry]
    def get_object_by_dest_dn(dn) -> Optional[MigrationMapEntry]
    def update_object_status(source_guid, status, notes)
    
    # Deferred references
    def add_deferred_reference(parent_guid, attr_name, ref_dn, run_id)
    def get_unresolved_references() -> List[DeferredReference]
    def mark_reference_resolved(ref_id, dest_dn, run_id)
    
    # Conflicts
    def add_conflict(source_dn, dest_dn, conflict_type, run_id)
    def get_conflicts(run_id) -> List[Conflict]
    
    # Errors
    def log_error(run_id, phase, obj_dn, error_msg, severity)
    
    # Statistics
    def get_statistics(run_id) -> Dict[str, Any]
```

### 4. Utils Layer

**Файлы**: `utils/`

#### DNUtils
```python
class DNUtils:
    @staticmethod
    def parse_dn(dn) -> List[Tuple[str, str]]  # [(RDN_type, value), ...]
    
    @staticmethod
    def convert_dn(source_dn, source_domain, dest_domain) -> str
    # CN=user,OU=IT,DC=source,DC=alt -> CN=user,OU=IT,DC=dest,DC=alt
    
    @staticmethod
    def get_parent_dn(dn) -> str
    
    @staticmethod
    def get_rdn(dn) -> str  # CN=user
    
    @staticmethod
    def get_depth(dn) -> int  # count of commas
```

#### PasswordGenerator
```python
class PasswordGenerator:
    @staticmethod
    def generate(length=12, charset=None) -> str
```

#### Logger
```python
class MigrationLogger:
    def __init__(log_file, gui_callback=None)
    
    def info(msg)
    def success(msg)
    def warning(msg)
    def error(msg)
    def conflict(msg)
    
    def set_phase(phase_name)
```

**Логирование:**
- File: `logs/migration_YYYYMMDD_HHMMSS.log`
- GUI: callback для real-time отображения
- Levels: INFO, SUCCESS, WARNING, ERROR, CONFLICT

#### ReportGenerator
```python
class ReportGenerator:
    def generate_html_report(migration_db, run_id, output_path)
    def generate_text_report(migration_db, run_id, output_path)
```

**Структура отчета:**
- Summary statistics
- Created objects (by type)
- Existing objects (skipped)
- Conflicts
- Deferred references
- Errors

## Поток данных

### High-Level Flow

```
User Input (GUI)
    ↓
ConnectionDialog → LDAPConnector (test connections)
    ↓
MainWindow: Specify Base DN
    ↓
Analyzer.analyze(base_dn)
    ↓ (analysis result)
PreviewDialog: Show plan
    ↓ (user confirms)
Migrator.migrate(base_dn)
    ↓
    Phase 1: Create OUs
    ↓
    Phase 2: Create Objects
    ↓
    Phase 3: Copy Attributes
    ↓
    Phase 4: Resolve References
    ↓
    Phase 5: Verify
    ↓
MigrationDB: Update statistics
    ↓
ReportGenerator: Generate report
    ↓
GUI: Display results
```

### Data Flow Details

**Анализ:**
```
Base DN → LDAP Search (source) → Raw LDAP entries
    ↓
Analyzer.classify_object() → Typed objects (OU/User/Group/Contact)
    ↓
Filter (ignored patterns) → Filtered list
    ↓
Build hierarchy → Dependency tree
    ↓
Analysis Result → GUI (preview)
```

**Миграция объекта:**
```
Source LDAP Entry
    ↓
ObjectHandler.create() → LDAP add (destination)
    ↓
MigrationDB.add_object() → Record mapping
    ↓
ObjectHandler.copy_attributes() → Read attrs from source
    ↓
AttributeMapper.transform() → Transform values
    ↓
LDAP modify (destination) → Write attrs
    ↓
ObjectHandler.get_reference_attributes() → Extract refs
    ↓
ReferenceResolver.resolve_reference() → Check migration_map
    ↓
    If found: LDAP modify (add reference)
    If not: MigrationDB.add_deferred_reference()
```

## База данных миграции

### Таблица: migration_runs
**Назначение**: Журнал запусков миграции

**Ключевые поля:**
- `run_id`: Уникальный ID запуска
- `source_base_dn`: Исходный DN для миграции
- `status`: in_progress / completed / failed
- Счетчики: objects_created, objects_skipped, objects_conflicted

### Таблица: migration_map
**Назначение**: Главная таблица соответствия объектов

**Ключевые поля:**
- `source_guid`: objectGUID из source (UNIQUE)
- `source_dn`: DN в source
- `dest_guid`: objectGUID в destination
- `dest_dn`: DN в destination
- `object_type`: user/group/ou/contact
- `status`: created/exists/conflict/error

**Использование:**
- Lookup при разрешении ссылок
- Проверка идемпотентности (объект уже мигрирован?)
- Отчетность

### Таблица: deferred_references
**Назначение**: Отложенные ссылки (target вне scope)

**Ключевые поля:**
- `parent_object_guid`: Объект с ссылкой (например, группа)
- `attribute_name`: Имя атрибута (member, manager)
- `referenced_source_dn`: DN целевого объекта в source
- `resolved`: Boolean (разрешена ли ссылка?)

**Workflow:**
1. Phase 4: Обнаружена ссылка на объект вне scope → insert
2. Следующий запуск: Проверить `referenced_source_dn` в `migration_map`
3. Если найден → LDAP modify, установить `resolved=1`

### Таблица: conflicts
**Назначение**: Объекты-конфликты

**Сценарий:**
- Объект существует в destination по DN
- Но НЕ записан в `migration_map`
- Вероятно создан вручную или другим процессом

**Действие:**
- НЕ перезаписывать
- Записать в conflicts
- Логировать как CONFLICT

## Обработка ссылочных атрибутов

### Типы ссылочных атрибутов

1. **member** (группы)
   - Multi-valued
   - Может указывать на объекты вне scope
   
2. **manager** (пользователи)
   - Single-valued
   - Обычно внутри организации
   
3. **managedBy** (OU, группы)
   - Single-valued

### Алгоритм разрешения

```python
def resolve_references(obj, migration_db):
    ref_attrs = obj.get_reference_attributes()
    
    for attr_name in ref_attrs:
        values = obj.get_attribute(attr_name)  # может быть multi-valued
        
        resolved_values = []
        deferred_values = []
        
        for ref_dn in values:
            # Lookup in migration_map
            map_entry = migration_db.get_object_by_source_dn(ref_dn)
            
            if map_entry:
                # Target объект уже мигрирован
                resolved_values.append(map_entry.dest_dn)
            else:
                # Target объект еще не мигрирован (или вне scope)
                deferred_values.append(ref_dn)
                migration_db.add_deferred_reference(
                    parent_guid=obj.source_guid,
                    attr_name=attr_name,
                    ref_dn=ref_dn,
                    run_id=current_run_id
                )
        
        # Установить те ссылки, которые удалось разрешить
        if resolved_values:
            dest_conn.modify(obj.dest_dn, {attr_name: [(MODIFY_REPLACE, resolved_values)]})
```

### Пример: Группа с членами вне scope

**Source:**
```
DN: CN=Sales,OU=Level2,OU=Level1,DC=source,DC=alt
member: CN=user1,OU=Level2,OU=Level1,DC=source,DC=alt  # PRESENT
member: CN=user2,OU=Level2,OU=Level1,DC=source,DC=alt  # PRESENT
member: CN=user5,OU=Level5,DC=source,DC=alt            # OUT OF SCOPE
```

**Первый запуск (migrate OU=Level2,...):**

1. Создать группу Sales в destination
2. Обработать members:
   - user1: найден в migration_map → добавить
   - user2: найден в migration_map → добавить
   - user5: НЕ найден → записать в deferred_references
3. LDAP modify: добавить user1, user2 в group.member

**Второй запуск (migrate OU=Level5):**

1. Создать user5 в destination
2. Записать в migration_map

**Третий запуск (migrate OU=Level2,... снова):**

1. Группа Sales: уже существует (status=exists)
2. Проверить deferred_references для Sales:
   - user5: теперь найден в migration_map!
3. LDAP modify: добавить user5 в group.member
4. Обновить deferred_references: resolved=1

## Идемпотентность

### Принципы

1. **Повторный запуск безопасен**: не ломает уже мигрированные объекты
2. **Инкрементальность**: каждый запуск дополняет предыдущие
3. **Stateful**: migration_db сохраняет состояние между запусками

### Проверки при повторном запуске

```python
def process_object(source_obj, migration_db, dest_conn):
    # 1. Проверить в migration_map
    map_entry = migration_db.get_object_by_source_guid(source_obj.guid)
    
    if map_entry:
        # Объект уже мигрирован ранее
        logger.info(f"{source_obj.dn} - EXISTS (status={map_entry.status})")
        
        # Обновить last_seen
        migration_db.update_object_status(
            source_guid=source_obj.guid,
            status='exists',
            notes=f'Seen in run {current_run_id}'
        )
        
        # Проверить deferred references
        process_deferred_references_for_object(source_obj, migration_db, dest_conn)
        
        return 'EXISTS'
    
    else:
        # Новый объект (не в migration_map)
        dest_dn = convert_dn(source_obj.dn)
        
        # Проверить: существует ли в destination физически?
        dest_obj = dest_conn.get_object_by_dn(dest_dn)
        
        if dest_obj:
            # CONFLICT: объект есть, но не отслеживается
            logger.conflict(f"{source_obj.dn} - CONFLICT (exists in dest, not tracked)")
            migration_db.add_conflict(source_obj.dn, dest_dn, 'exists_not_tracked', run_id)
            return 'CONFLICT'
        
        else:
            # Создать новый объект
            create_object(source_obj, dest_conn)
            migration_db.add_object(...)
            return 'CREATED'
```

### Счетчики миграции

При каждом запуске обновляются счетчики в `migration_runs`:
- `objects_analyzed`: Общее количество объектов в source
- `objects_created`: Создано в этом запуске
- `objects_updated`: Обновлено (например, добавлены deferred members)
- `objects_skipped`: Пропущено (already exists)
- `objects_conflicted`: Конфликты

## Обработка ошибок

### Уровни ошибок

1. **WARNING**: Неожиданная ситуация, но не блокирующая
   - Пример: Атрибут не может быть скопирован (schema mismatch)
   
2. **ERROR**: Ошибка обработки объекта
   - Пример: LDAP add failed
   - Действие: Пропустить объект, записать в migration_errors
   
3. **CRITICAL**: Фатальная ошибка
   - Пример: Потеря подключения к DC
   - Действие: Остановить миграцию, установить status=failed

### Стратегии

#### Per-Object Error Handling
```python
try:
    create_object(source_obj, dest_conn)
except LDAPException as e:
    logger.error(f"Failed to create {source_obj.dn}: {e}")
    migration_db.log_error(
        run_id=current_run_id,
        phase='object_creation',
        obj_dn=source_obj.dn,
        error_msg=str(e),
        severity='error'
    )
    # Продолжить со следующим объектом
    return 'ERROR'
```

#### Phase-Level Error Handling
```python
try:
    phase1_create_ous(ou_list)
except Exception as e:
    logger.critical(f"Phase 1 failed: {e}")
    migration_db.update_migration_run(run_id, status='failed')
    raise  # Stop migration
```

### Rollback

**Вопрос**: Нужен ли rollback при ошибке?

**Решение**: НЕТ автоматического rollback
- Сложность: Удалить уже созданные объекты в destination
- Риск: Можем удалить объекты, созданные вручную (conflicts)
- Рекомендация: Manual cleanup при необходимости

**Альтернатива**: "Dry-run" mode
- Опция: выполнить анализ и preview БЕЗ фактического создания
- Полезно для тестирования

## Вопросы для уточнения

1. **Dry-run режим**: Нужен ли режим "симуляции" (анализ без создания объектов)?

2. **Batch size**: Стоит ли обрабатывать объекты батчами (например, по 100) для больших миграций?

3. **Concurrency**: Возможность параллельной обработки объектов (threading/multiprocessing)?

4. **Backup**: Нужен ли механизм backup SQLite БД перед каждым запуском?

5. **Attribute validation**: Глубокая валидация атрибутов перед копированием (например, проверка email format)?

6. **Logging level**: Настраиваемый уровень логирования (DEBUG/INFO/WARNING/ERROR)?

7. **Connection pooling**: Для больших миграций — переиспользование LDAP соединений?

8. **Resume capability**: Возможность возобновить прерванную миграцию (checkpoint)?

9. **Incremental attribute sync**: Обновлять атрибуты существующих объектов, если они изменились в source?

10. **Multi-domain support**: В будущем — поддержка нескольких source/destination пар?

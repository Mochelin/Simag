<?php
/**
 * GestionUsuario.php
 * 
 * Módulo de Gestión de Usuarios para Simag
 * Sistema de administración de usuarios con soporte para SQL Server
 * 
 * @author Simag Team
 * @version 2.0
 * 
 * Características:
 * - Creación, edición y desactivación de usuarios
 * - Asignación múltiple de roles
 * - Validación de RUT chileno
 * - Manejo seguro de contraseñas
 * - Compatibilidad con SQL Server 2016+
 * - Protección CSRF en todas las operaciones AJAX
 */

// Configuración de errores para producción
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Iniciar sesión si no está iniciada
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Constantes de configuración
define('DEFAULT_PASSWORD', 'Simag2025');
define('MIN_PASSWORD_LENGTH', 8);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minutos en segundos

/**
 * Clase principal para gestión de usuarios
 */
class GestionUsuario
{
    private $conn;
    private $lastError;
    private $lastErrorCode;

    /**
     * Constructor - Establece conexión a la base de datos
     * 
     * @param PDO $connection Conexión PDO existente (opcional)
     */
    public function __construct($connection = null)
    {
        if ($connection !== null) {
            $this->conn = $connection;
        } else {
            $this->initConnection();
        }
        $this->lastError = '';
        $this->lastErrorCode = 0;
    }

    /**
     * Inicializa la conexión a SQL Server
     * 
     * @throws Exception Si falla la conexión
     */
    private function initConnection()
    {
        // Obtener configuración de base de datos
        $config = $this->getDbConfig();
        
        try {
            $dsn = "sqlsrv:Server={$config['server']};Database={$config['database']}";
            $this->conn = new PDO(
                $dsn,
                $config['username'],
                $config['password'],
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::SQLSRV_ATTR_ENCODING => PDO::SQLSRV_ENCODING_UTF8
                ]
            );
        } catch (PDOException $e) {
            $this->logError('Error de conexión: ' . $e->getMessage());
            throw new Exception('Error al conectar con la base de datos');
        }
    }

    /**
     * Obtiene la configuración de base de datos
     * 
     * @return array Configuración de conexión
     */
    private function getDbConfig()
    {
        // En producción, estos valores deberían venir de un archivo de configuración
        // o variables de entorno
        return [
            'server' => getenv('DB_SERVER') ?: 'localhost',
            'database' => getenv('DB_DATABASE') ?: 'SimagDB',
            'username' => getenv('DB_USERNAME') ?: 'sa',
            'password' => getenv('DB_PASSWORD') ?: ''
        ];
    }

    /**
     * Registra errores en el log del sistema
     * 
     * @param string $message Mensaje de error
     * @param string $level Nivel de severidad (ERROR, WARNING, INFO)
     */
    private function logError($message, $level = 'ERROR')
    {
        $timestamp = date('Y-m-d H:i:s');
        $logMessage = "[{$timestamp}] [{$level}] GestionUsuario: {$message}";
        error_log($logMessage);
    }

    // =========================================================================
    // VALIDACIONES
    // =========================================================================

    /**
     * Genera un token CSRF
     * 
     * @return string Token CSRF
     */
    public static function generateCsrfToken()
    {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    /**
     * Valida el token CSRF
     * 
     * @param string $token Token a validar
     * @return bool True si el token es válido
     */
    public static function validateCsrfToken($token)
    {
        if (empty($token) || !isset($_SESSION['csrf_token'])) {
            return false;
        }
        return hash_equals($_SESSION['csrf_token'], $token);
    }

    /**
     * Regenera el token CSRF (después de operaciones sensibles)
     * 
     * @return string Nuevo token CSRF
     */
    public static function regenerateCsrfToken()
    {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return $_SESSION['csrf_token'];
    }

    /**
     * Valida el formato de RUT chileno
     * Formato aceptado: XX.XXX.XXX-X o XXXXXXXX-X
     * 
     * @param string $rut RUT a validar
     * @return bool True si el formato es válido
     */
    public function validateRut($rut)
    {
        if (empty($rut)) {
            return false;
        }

        // Eliminar puntos y guiones para validación
        $rutClean = str_replace(['.', '-'], '', strtoupper(trim($rut)));
        
        // Verificar longitud mínima
        if (strlen($rutClean) < 8 || strlen($rutClean) > 9) {
            return false;
        }

        // Separar número y dígito verificador
        $dv = substr($rutClean, -1);
        $numero = substr($rutClean, 0, -1);

        // Validar que el número sea numérico
        if (!ctype_digit($numero)) {
            return false;
        }

        // Calcular dígito verificador
        $dvCalculado = $this->calculateRutDv($numero);

        return $dv === $dvCalculado;
    }

    /**
     * Calcula el dígito verificador de un RUT
     * 
     * @param string $numero Número del RUT sin dígito verificador
     * @return string Dígito verificador calculado
     */
    private function calculateRutDv($numero)
    {
        $suma = 0;
        $multiplo = 2;

        for ($i = strlen($numero) - 1; $i >= 0; $i--) {
            $suma += intval($numero[$i]) * $multiplo;
            $multiplo = $multiplo < 7 ? $multiplo + 1 : 2;
        }

        $resto = $suma % 11;
        $dv = 11 - $resto;

        if ($dv == 11) return '0';
        if ($dv == 10) return 'K';
        return strval($dv);
    }

    /**
     * Formatea un RUT al formato estándar XX.XXX.XXX-X
     * 
     * @param string $rut RUT a formatear
     * @return string RUT formateado
     */
    public function formatRut($rut)
    {
        $rutClean = str_replace(['.', '-'], '', strtoupper(trim($rut)));
        
        if (strlen($rutClean) < 2) {
            return $rut;
        }

        $dv = substr($rutClean, -1);
        $numero = substr($rutClean, 0, -1);
        
        // Formatear con puntos
        $numeroFormateado = number_format(intval($numero), 0, '', '.');
        
        return $numeroFormateado . '-' . $dv;
    }

    /**
     * Valida el formato de email
     * 
     * @param string $email Email a validar
     * @return bool True si el formato es válido
     */
    public function validateEmail($email)
    {
        if (empty($email)) {
            return false;
        }
        return filter_var(trim($email), FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Valida el formato de fecha
     * Formatos aceptados: YYYY-MM-DD, DD-MM-YYYY, DD/MM/YYYY
     * 
     * @param string $date Fecha a validar
     * @param string $format Formato esperado (default: Y-m-d)
     * @return bool True si la fecha es válida
     */
    public function validateDate($date, $format = 'Y-m-d')
    {
        if (empty($date)) {
            return true; // Fecha opcional
        }

        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) === $date;
    }

    /**
     * Valida el nombre de usuario
     * Debe tener entre 4 y 50 caracteres, solo alfanuméricos y guiones bajos
     * 
     * @param string $username Nombre de usuario a validar
     * @return bool True si es válido
     */
    public function validateUsername($username)
    {
        if (empty($username)) {
            return false;
        }

        $username = trim($username);
        
        // Verificar longitud
        if (strlen($username) < 4 || strlen($username) > 50) {
            return false;
        }

        // Solo letras, números, puntos y guiones bajos
        return preg_match('/^[a-zA-Z0-9._]+$/', $username) === 1;
    }

    /**
     * Valida la fortaleza de la contraseña
     * 
     * @param string $password Contraseña a validar
     * @return array ['valid' => bool, 'message' => string]
     */
    public function validatePassword($password)
    {
        if (strlen($password) < MIN_PASSWORD_LENGTH) {
            return [
                'valid' => false,
                'message' => 'La contraseña debe tener al menos ' . MIN_PASSWORD_LENGTH . ' caracteres'
            ];
        }

        // Verificar complejidad (al menos una mayúscula, una minúscula y un número)
        if (!preg_match('/[A-Z]/', $password)) {
            return [
                'valid' => false,
                'message' => 'La contraseña debe contener al menos una letra mayúscula'
            ];
        }

        if (!preg_match('/[a-z]/', $password)) {
            return [
                'valid' => false,
                'message' => 'La contraseña debe contener al menos una letra minúscula'
            ];
        }

        if (!preg_match('/[0-9]/', $password)) {
            return [
                'valid' => false,
                'message' => 'La contraseña debe contener al menos un número'
            ];
        }

        return ['valid' => true, 'message' => ''];
    }

    /**
     * Sanitiza una cadena de entrada
     * 
     * @param string $input Cadena a sanitizar
     * @param int $maxLength Longitud máxima (default: 255)
     * @return string Cadena sanitizada
     */
    public function sanitizeInput($input, $maxLength = 255)
    {
        if ($input === null) {
            return '';
        }

        // Eliminar espacios extra y caracteres de control
        $input = trim($input);
        $input = preg_replace('/[\x00-\x1F\x7F]/', '', $input);
        
        // Limitar longitud
        if (strlen($input) > $maxLength) {
            $input = substr($input, 0, $maxLength);
        }

        return $input;
    }

    // =========================================================================
    // MANEJO DE CONTRASEÑAS
    // =========================================================================

    /**
     * Genera un hash seguro de contraseña
     * 
     * @param string $password Contraseña en texto plano
     * @return string Hash de la contraseña
     */
    public function hashPassword($password)
    {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    /**
     * Verifica una contraseña contra su hash
     * 
     * @param string $password Contraseña en texto plano
     * @param string $hash Hash almacenado
     * @return bool True si la contraseña es correcta
     */
    public function verifyPassword($password, $hash)
    {
        return password_verify($password, $hash);
    }

    /**
     * Convierte el hash de contraseña para almacenamiento en VARBINARY
     * SQL Server almacena los hashes como VARBINARY para compatibilidad
     * 
     * @param string $hash Hash de la contraseña
     * @return string Hash preparado para SQL Server
     */
    private function preparePasswordForStorage($hash)
    {
        // El hash de bcrypt es una cadena de 60 caracteres
        // Se almacena como VARBINARY para evitar problemas de encoding
        return $hash;
    }

    /**
     * Recupera y convierte el hash de contraseña desde VARBINARY
     * 
     * @param mixed $storedHash Hash almacenado en la base de datos
     * @return string Hash recuperado como string
     */
    private function retrievePasswordFromStorage($storedHash)
    {
        // Si viene como recurso (stream), leer el contenido
        if (is_resource($storedHash)) {
            $storedHash = stream_get_contents($storedHash);
        }
        
        // Si viene como binario, convertir a string
        if (is_string($storedHash)) {
            // Verificar si ya es un hash bcrypt válido
            if (strpos($storedHash, '$2y$') === 0 || strpos($storedHash, '$2a$') === 0) {
                return $storedHash;
            }
        }
        
        return $storedHash;
    }

    // =========================================================================
    // OPERACIONES CRUD DE USUARIOS
    // =========================================================================

    /**
     * Obtiene todos los usuarios con filtros opcionales
     * 
     * @param array $filters Filtros opcionales (estado, rol, busqueda)
     * @param int $page Número de página
     * @param int $perPage Resultados por página
     * @return array Lista de usuarios
     */
    public function getUsers($filters = [], $page = 1, $perPage = 10)
    {
        try {
            $whereConditions = [];
            $params = [];

            // Filtro por estado
            if (isset($filters['estado']) && $filters['estado'] !== '') {
                $whereConditions[] = 'u.Activo = :estado';
                $params[':estado'] = intval($filters['estado']);
            }

            // Filtro por rol
            if (isset($filters['rol']) && $filters['rol'] !== '') {
                $whereConditions[] = 'EXISTS (SELECT 1 FROM UsuarioRol ur2 WHERE ur2.IdUsuario = u.IdUsuario AND ur2.IdRol = :rol)';
                $params[':rol'] = intval($filters['rol']);
            }

            // Filtro de búsqueda
            if (isset($filters['busqueda']) && $filters['busqueda'] !== '') {
                $busqueda = '%' . $this->sanitizeInput($filters['busqueda']) . '%';
                $whereConditions[] = '(u.NombreUsuario LIKE :busqueda OR u.Nombre LIKE :busqueda2 OR u.Apellido LIKE :busqueda3 OR u.Rut LIKE :busqueda4 OR u.Email LIKE :busqueda5)';
                $params[':busqueda'] = $busqueda;
                $params[':busqueda2'] = $busqueda;
                $params[':busqueda3'] = $busqueda;
                $params[':busqueda4'] = $busqueda;
                $params[':busqueda5'] = $busqueda;
            }

            $whereClause = count($whereConditions) > 0 ? 'WHERE ' . implode(' AND ', $whereConditions) : '';

            // Calcular offset para paginación
            $offset = ($page - 1) * $perPage;

            // Consulta principal con paginación (compatible con SQL Server 2012+)
            $sql = "
                SELECT 
                    u.IdUsuario,
                    u.NombreUsuario,
                    u.Nombre,
                    u.Apellido,
                    u.Rut,
                    u.Email,
                    u.Telefono,
                    u.FechaNacimiento,
                    u.Activo,
                    u.FechaCreacion,
                    u.FechaModificacion,
                    COALESCE(
                        (SELECT STRING_AGG(r.NombreRol, ', ') 
                         FROM UsuarioRol ur 
                         INNER JOIN Rol r ON ur.IdRol = r.IdRol 
                         WHERE ur.IdUsuario = u.IdUsuario),
                        'Sin rol'
                    ) AS Roles,
                    COALESCE(
                        (SELECT TOP 1 r.NombreRol 
                         FROM UsuarioRol ur 
                         INNER JOIN Rol r ON ur.IdRol = r.IdRol 
                         WHERE ur.IdUsuario = u.IdUsuario AND ur.EsPrincipal = 1),
                        'Sin rol principal'
                    ) AS RolPrincipal
                FROM Usuario u
                {$whereClause}
                ORDER BY u.FechaCreacion DESC
                OFFSET :offset ROWS FETCH NEXT :perPage ROWS ONLY
            ";

            $stmt = $this->conn->prepare($sql);
            foreach ($params as $key => $value) {
                $stmt->bindValue($key, $value);
            }
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->bindValue(':perPage', $perPage, PDO::PARAM_INT);
            $stmt->execute();

            $users = $stmt->fetchAll();

            // Obtener total de registros para paginación
            $sqlCount = "SELECT COUNT(*) as total FROM Usuario u {$whereClause}";
            $stmtCount = $this->conn->prepare($sqlCount);
            foreach ($params as $key => $value) {
                $stmtCount->bindValue($key, $value);
            }
            $stmtCount->execute();
            $total = $stmtCount->fetch()['total'];

            return [
                'success' => true,
                'data' => $users,
                'pagination' => [
                    'total' => $total,
                    'page' => $page,
                    'perPage' => $perPage,
                    'totalPages' => ceil($total / $perPage)
                ]
            ];

        } catch (PDOException $e) {
            $this->logError('Error al obtener usuarios: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error al obtener la lista de usuarios',
                'data' => []
            ];
        }
    }

    /**
     * Obtiene un usuario por su ID
     * 
     * @param int $idUsuario ID del usuario
     * @return array Datos del usuario o error
     */
    public function getUserById($idUsuario)
    {
        try {
            $idUsuario = intval($idUsuario);
            
            if ($idUsuario <= 0) {
                return [
                    'success' => false,
                    'message' => 'ID de usuario inválido'
                ];
            }

            $sql = "
                SELECT 
                    u.IdUsuario,
                    u.NombreUsuario,
                    u.Nombre,
                    u.Apellido,
                    u.Rut,
                    u.Email,
                    u.Telefono,
                    u.FechaNacimiento,
                    u.Activo,
                    u.FechaCreacion,
                    u.FechaModificacion
                FROM Usuario u
                WHERE u.IdUsuario = :idUsuario
            ";

            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':idUsuario', $idUsuario, PDO::PARAM_INT);
            $stmt->execute();

            $user = $stmt->fetch();

            if (!$user) {
                return [
                    'success' => false,
                    'message' => 'Usuario no encontrado'
                ];
            }

            // Obtener roles del usuario
            $user['Roles'] = $this->getUserRoles($idUsuario);

            return [
                'success' => true,
                'data' => $user
            ];

        } catch (PDOException $e) {
            $this->logError('Error al obtener usuario: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error al obtener los datos del usuario'
            ];
        }
    }

    /**
     * Obtiene los roles asignados a un usuario
     * 
     * @param int $idUsuario ID del usuario
     * @return array Lista de roles con indicador de principal
     */
    public function getUserRoles($idUsuario)
    {
        try {
            $sql = "
                SELECT 
                    r.IdRol,
                    r.NombreRol,
                    r.Descripcion,
                    COALESCE(ur.EsPrincipal, 0) AS EsPrincipal
                FROM UsuarioRol ur
                INNER JOIN Rol r ON ur.IdRol = r.IdRol
                WHERE ur.IdUsuario = :idUsuario
                ORDER BY ur.EsPrincipal DESC, r.NombreRol ASC
            ";

            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':idUsuario', intval($idUsuario), PDO::PARAM_INT);
            $stmt->execute();

            return $stmt->fetchAll();

        } catch (PDOException $e) {
            $this->logError('Error al obtener roles del usuario: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Obtiene todos los roles disponibles
     * 
     * @return array Lista de roles
     */
    public function getAllRoles()
    {
        try {
            $sql = "SELECT IdRol, NombreRol, Descripcion, Activo FROM Rol WHERE Activo = 1 ORDER BY NombreRol";
            $stmt = $this->conn->query($sql);
            return [
                'success' => true,
                'data' => $stmt->fetchAll()
            ];
        } catch (PDOException $e) {
            $this->logError('Error al obtener roles: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error al obtener los roles',
                'data' => []
            ];
        }
    }

    /**
     * Verifica si existe un usuario con el mismo nombre de usuario o RUT
     * 
     * @param string $nombreUsuario Nombre de usuario
     * @param string $rut RUT
     * @param int|null $excludeId ID de usuario a excluir (para edición)
     * @return array ['exists' => bool, 'field' => string]
     */
    public function checkDuplicateUser($nombreUsuario, $rut, $excludeId = null)
    {
        try {
            $params = [];
            $excludeCondition = '';

            if ($excludeId !== null) {
                $excludeCondition = ' AND IdUsuario != :excludeId';
                $params[':excludeId'] = intval($excludeId);
            }

            // Verificar nombre de usuario
            $sql = "SELECT COUNT(*) as count FROM Usuario WHERE NombreUsuario = :nombreUsuario" . $excludeCondition;
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':nombreUsuario', $this->sanitizeInput($nombreUsuario));
            foreach ($params as $key => $value) {
                $stmt->bindValue($key, $value);
            }
            $stmt->execute();
            
            if ($stmt->fetch()['count'] > 0) {
                return ['exists' => true, 'field' => 'nombreUsuario', 'message' => 'El nombre de usuario ya existe'];
            }

            // Verificar RUT
            $rutClean = str_replace(['.', '-'], '', strtoupper(trim($rut)));
            $sql = "SELECT COUNT(*) as count FROM Usuario WHERE REPLACE(REPLACE(Rut, '.', ''), '-', '') = :rut" . $excludeCondition;
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':rut', $rutClean);
            foreach ($params as $key => $value) {
                $stmt->bindValue($key, $value);
            }
            $stmt->execute();

            if ($stmt->fetch()['count'] > 0) {
                return ['exists' => true, 'field' => 'rut', 'message' => 'El RUT ya está registrado'];
            }

            return ['exists' => false, 'field' => '', 'message' => ''];

        } catch (PDOException $e) {
            $this->logError('Error al verificar duplicados: ' . $e->getMessage());
            return ['exists' => false, 'field' => '', 'message' => ''];
        }
    }

    /**
     * Crea un nuevo usuario
     * 
     * @param array $userData Datos del usuario
     * @param array $roles IDs de roles a asignar
     * @param int|null $rolPrincipal ID del rol principal
     * @return array Resultado de la operación
     */
    public function createUser($userData, $roles = [], $rolPrincipal = null)
    {
        try {
            // Validaciones
            $validation = $this->validateUserData($userData, true);
            if (!$validation['valid']) {
                return [
                    'success' => false,
                    'message' => $validation['message']
                ];
            }

            // Verificar duplicados
            $duplicate = $this->checkDuplicateUser($userData['nombreUsuario'], $userData['rut']);
            if ($duplicate['exists']) {
                return [
                    'success' => false,
                    'message' => $duplicate['message']
                ];
            }

            // Iniciar transacción
            $this->conn->beginTransaction();

            // Generar hash de contraseña
            $password = isset($userData['password']) && !empty($userData['password']) 
                ? $userData['password'] 
                : DEFAULT_PASSWORD;
            
            $passwordHash = $this->hashPassword($password);

            // Preparar datos
            $nombre = $this->sanitizeInput($userData['nombre']);
            $apellido = $this->sanitizeInput($userData['apellido']);
            $nombreUsuario = $this->sanitizeInput($userData['nombreUsuario']);
            $rut = $this->formatRut($userData['rut']);
            $email = $this->sanitizeInput($userData['email']);
            $telefono = isset($userData['telefono']) ? $this->sanitizeInput($userData['telefono']) : null;
            $fechaNacimiento = isset($userData['fechaNacimiento']) && !empty($userData['fechaNacimiento']) 
                ? $userData['fechaNacimiento'] 
                : null;
            $activo = isset($userData['activo']) ? intval($userData['activo']) : 1;

            // Insertar usuario
            // El hash de contraseña se almacena como VARCHAR para mantener compatibilidad
            // con password_verify() que requiere el hash como string
            $sql = "
                INSERT INTO Usuario (
                    NombreUsuario, 
                    Password, 
                    Nombre, 
                    Apellido, 
                    Rut, 
                    Email, 
                    Telefono, 
                    FechaNacimiento, 
                    Activo, 
                    FechaCreacion, 
                    FechaModificacion
                )
                VALUES (
                    :nombreUsuario,
                    CONVERT(VARBINARY(255), :password),
                    :nombre,
                    :apellido,
                    :rut,
                    :email,
                    :telefono,
                    :fechaNacimiento,
                    :activo,
                    GETDATE(),
                    GETDATE()
                )
            ";

            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':nombreUsuario', $nombreUsuario);
            $stmt->bindValue(':password', $passwordHash);
            $stmt->bindValue(':nombre', $nombre);
            $stmt->bindValue(':apellido', $apellido);
            $stmt->bindValue(':rut', $rut);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':telefono', $telefono);
            $stmt->bindValue(':fechaNacimiento', $fechaNacimiento);
            $stmt->bindValue(':activo', $activo, PDO::PARAM_INT);
            $stmt->execute();

            // Obtener ID del usuario insertado
            $idUsuario = $this->getLastInsertId();

            if (!$idUsuario) {
                throw new Exception('Error al obtener el ID del usuario creado');
            }

            // Asignar roles
            if (!empty($roles)) {
                $this->assignRoles($idUsuario, $roles, $rolPrincipal);
            }

            $this->conn->commit();

            $this->logError("Usuario creado exitosamente: ID {$idUsuario}", 'INFO');

            return [
                'success' => true,
                'message' => 'Usuario creado exitosamente',
                'data' => ['idUsuario' => $idUsuario]
            ];

        } catch (PDOException $e) {
            $this->conn->rollBack();
            $this->logError('Error al crear usuario: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error al crear el usuario. Por favor, intente nuevamente.'
            ];
        } catch (Exception $e) {
            $this->conn->rollBack();
            $this->logError('Error al crear usuario: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Obtiene el último ID insertado
     * Compatible con SQL Server usando SCOPE_IDENTITY()
     * 
     * @return int|null ID del último registro insertado
     */
    private function getLastInsertId()
    {
        try {
            $stmt = $this->conn->query("SELECT SCOPE_IDENTITY() AS id");
            $result = $stmt->fetch();
            return $result ? intval($result['id']) : null;
        } catch (PDOException $e) {
            $this->logError('Error al obtener último ID: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Actualiza un usuario existente
     * 
     * @param int $idUsuario ID del usuario
     * @param array $userData Datos del usuario
     * @param array $roles IDs de roles a asignar
     * @param int|null $rolPrincipal ID del rol principal
     * @return array Resultado de la operación
     */
    public function updateUser($idUsuario, $userData, $roles = [], $rolPrincipal = null)
    {
        try {
            $idUsuario = intval($idUsuario);
            
            if ($idUsuario <= 0) {
                return [
                    'success' => false,
                    'message' => 'ID de usuario inválido'
                ];
            }

            // Verificar que el usuario existe
            $existingUser = $this->getUserById($idUsuario);
            if (!$existingUser['success']) {
                return [
                    'success' => false,
                    'message' => 'Usuario no encontrado'
                ];
            }

            // Validaciones
            $validation = $this->validateUserData($userData, false);
            if (!$validation['valid']) {
                return [
                    'success' => false,
                    'message' => $validation['message']
                ];
            }

            // Verificar duplicados (excluyendo el usuario actual)
            $duplicate = $this->checkDuplicateUser($userData['nombreUsuario'], $userData['rut'], $idUsuario);
            if ($duplicate['exists']) {
                return [
                    'success' => false,
                    'message' => $duplicate['message']
                ];
            }

            // Iniciar transacción
            $this->conn->beginTransaction();

            // Preparar datos
            $nombre = $this->sanitizeInput($userData['nombre']);
            $apellido = $this->sanitizeInput($userData['apellido']);
            $nombreUsuario = $this->sanitizeInput($userData['nombreUsuario']);
            $rut = $this->formatRut($userData['rut']);
            $email = $this->sanitizeInput($userData['email']);
            $telefono = isset($userData['telefono']) ? $this->sanitizeInput($userData['telefono']) : null;
            $fechaNacimiento = isset($userData['fechaNacimiento']) && !empty($userData['fechaNacimiento']) 
                ? $userData['fechaNacimiento'] 
                : null;
            $activo = isset($userData['activo']) ? intval($userData['activo']) : 1;

            // Construir consulta de actualización
            $sql = "
                UPDATE Usuario SET
                    NombreUsuario = :nombreUsuario,
                    Nombre = :nombre,
                    Apellido = :apellido,
                    Rut = :rut,
                    Email = :email,
                    Telefono = :telefono,
                    FechaNacimiento = :fechaNacimiento,
                    Activo = :activo,
                    FechaModificacion = GETDATE()
                WHERE IdUsuario = :idUsuario
            ";

            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':nombreUsuario', $nombreUsuario);
            $stmt->bindValue(':nombre', $nombre);
            $stmt->bindValue(':apellido', $apellido);
            $stmt->bindValue(':rut', $rut);
            $stmt->bindValue(':email', $email);
            $stmt->bindValue(':telefono', $telefono);
            $stmt->bindValue(':fechaNacimiento', $fechaNacimiento);
            $stmt->bindValue(':activo', $activo, PDO::PARAM_INT);
            $stmt->bindValue(':idUsuario', $idUsuario, PDO::PARAM_INT);
            $stmt->execute();

            // Actualizar contraseña si se proporciona
            if (isset($userData['password']) && !empty($userData['password'])) {
                $this->updatePassword($idUsuario, $userData['password']);
            }

            // Actualizar roles
            $this->assignRoles($idUsuario, $roles, $rolPrincipal);

            $this->conn->commit();

            $this->logError("Usuario actualizado exitosamente: ID {$idUsuario}", 'INFO');

            return [
                'success' => true,
                'message' => 'Usuario actualizado exitosamente'
            ];

        } catch (PDOException $e) {
            $this->conn->rollBack();
            $this->logError('Error al actualizar usuario: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error al actualizar el usuario. Por favor, intente nuevamente.'
            ];
        } catch (Exception $e) {
            $this->conn->rollBack();
            $this->logError('Error al actualizar usuario: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        }
    }

    /**
     * Actualiza la contraseña de un usuario
     * 
     * @param int $idUsuario ID del usuario
     * @param string $newPassword Nueva contraseña
     * @return bool True si se actualizó correctamente
     */
    private function updatePassword($idUsuario, $newPassword)
    {
        $passwordHash = $this->hashPassword($newPassword);
        
        $sql = "UPDATE Usuario SET Password = CONVERT(VARBINARY(255), :password), FechaModificacion = GETDATE() WHERE IdUsuario = :idUsuario";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindValue(':password', $passwordHash);
        $stmt->bindValue(':idUsuario', intval($idUsuario), PDO::PARAM_INT);
        
        return $stmt->execute();
    }

    /**
     * Asigna roles a un usuario
     * 
     * @param int $idUsuario ID del usuario
     * @param array $roles IDs de roles a asignar
     * @param int|null $rolPrincipal ID del rol principal
     */
    private function assignRoles($idUsuario, $roles, $rolPrincipal = null)
    {
        // Eliminar roles actuales
        $sql = "DELETE FROM UsuarioRol WHERE IdUsuario = :idUsuario";
        $stmt = $this->conn->prepare($sql);
        $stmt->bindValue(':idUsuario', intval($idUsuario), PDO::PARAM_INT);
        $stmt->execute();

        // Asignar nuevos roles
        if (!empty($roles)) {
            $sql = "INSERT INTO UsuarioRol (IdUsuario, IdRol, EsPrincipal, FechaAsignacion) VALUES (:idUsuario, :idRol, :esPrincipal, GETDATE())";
            $stmt = $this->conn->prepare($sql);

            foreach ($roles as $idRol) {
                $idRol = intval($idRol);
                if ($idRol > 0) {
                    $esPrincipal = ($rolPrincipal !== null && intval($rolPrincipal) === $idRol) ? 1 : 0;
                    
                    $stmt->bindValue(':idUsuario', intval($idUsuario), PDO::PARAM_INT);
                    $stmt->bindValue(':idRol', $idRol, PDO::PARAM_INT);
                    $stmt->bindValue(':esPrincipal', $esPrincipal, PDO::PARAM_INT);
                    $stmt->execute();
                }
            }

            // Si no se especificó rol principal, asignar el primero como principal
            if ($rolPrincipal === null && count($roles) > 0) {
                $sql = "UPDATE UsuarioRol SET EsPrincipal = 1 WHERE IdUsuario = :idUsuario AND IdRol = :idRol";
                $stmt = $this->conn->prepare($sql);
                $stmt->bindValue(':idUsuario', intval($idUsuario), PDO::PARAM_INT);
                $stmt->bindValue(':idRol', intval($roles[0]), PDO::PARAM_INT);
                $stmt->execute();
            }
        }
    }

    /**
     * Valida los datos del usuario
     * 
     * @param array $userData Datos del usuario
     * @param bool $isNew True si es un usuario nuevo
     * @return array ['valid' => bool, 'message' => string]
     */
    private function validateUserData($userData, $isNew = true)
    {
        // Validar nombre de usuario
        if (!isset($userData['nombreUsuario']) || !$this->validateUsername($userData['nombreUsuario'])) {
            return [
                'valid' => false,
                'message' => 'El nombre de usuario debe tener entre 4 y 50 caracteres y solo puede contener letras, números, puntos y guiones bajos'
            ];
        }

        // Validar nombre
        if (!isset($userData['nombre']) || empty(trim($userData['nombre']))) {
            return [
                'valid' => false,
                'message' => 'El nombre es obligatorio'
            ];
        }

        // Validar apellido
        if (!isset($userData['apellido']) || empty(trim($userData['apellido']))) {
            return [
                'valid' => false,
                'message' => 'El apellido es obligatorio'
            ];
        }

        // Validar RUT
        if (!isset($userData['rut']) || !$this->validateRut($userData['rut'])) {
            return [
                'valid' => false,
                'message' => 'El RUT es inválido. Formato esperado: XX.XXX.XXX-X'
            ];
        }

        // Validar email
        if (!isset($userData['email']) || !$this->validateEmail($userData['email'])) {
            return [
                'valid' => false,
                'message' => 'El email es inválido'
            ];
        }

        // Validar fecha de nacimiento si se proporciona
        if (isset($userData['fechaNacimiento']) && !empty($userData['fechaNacimiento'])) {
            if (!$this->validateDate($userData['fechaNacimiento'])) {
                return [
                    'valid' => false,
                    'message' => 'La fecha de nacimiento es inválida. Formato esperado: AAAA-MM-DD'
                ];
            }
        }

        // Validar contraseña en usuarios nuevos (si se proporciona)
        if ($isNew && isset($userData['password']) && !empty($userData['password'])) {
            $passwordValidation = $this->validatePassword($userData['password']);
            if (!$passwordValidation['valid']) {
                return [
                    'valid' => false,
                    'message' => $passwordValidation['message']
                ];
            }
        }

        return ['valid' => true, 'message' => ''];
    }

    /**
     * Activa o desactiva un usuario
     * 
     * @param int $idUsuario ID del usuario
     * @param int $activo 1 para activar, 0 para desactivar
     * @return array Resultado de la operación
     */
    public function toggleUserStatus($idUsuario, $activo)
    {
        try {
            $idUsuario = intval($idUsuario);
            $activo = intval($activo) ? 1 : 0;

            if ($idUsuario <= 0) {
                return [
                    'success' => false,
                    'message' => 'ID de usuario inválido'
                ];
            }

            $sql = "UPDATE Usuario SET Activo = :activo, FechaModificacion = GETDATE() WHERE IdUsuario = :idUsuario";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':activo', $activo, PDO::PARAM_INT);
            $stmt->bindValue(':idUsuario', $idUsuario, PDO::PARAM_INT);
            $stmt->execute();

            $mensaje = $activo ? 'Usuario activado exitosamente' : 'Usuario desactivado exitosamente';
            $this->logError("{$mensaje}: ID {$idUsuario}", 'INFO');

            return [
                'success' => true,
                'message' => $mensaje
            ];

        } catch (PDOException $e) {
            $this->logError('Error al cambiar estado del usuario: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error al cambiar el estado del usuario'
            ];
        }
    }

    /**
     * Restablece la contraseña de un usuario al valor predeterminado
     * 
     * @param int $idUsuario ID del usuario
     * @return array Resultado de la operación
     */
    public function resetPassword($idUsuario)
    {
        try {
            $idUsuario = intval($idUsuario);

            if ($idUsuario <= 0) {
                return [
                    'success' => false,
                    'message' => 'ID de usuario inválido'
                ];
            }

            $this->conn->beginTransaction();
            
            $this->updatePassword($idUsuario, DEFAULT_PASSWORD);
            
            $this->conn->commit();

            $this->logError("Contraseña restablecida para usuario ID {$idUsuario}", 'INFO');

            return [
                'success' => true,
                'message' => 'Contraseña restablecida exitosamente. La nueva contraseña es: ' . DEFAULT_PASSWORD
            ];

        } catch (PDOException $e) {
            $this->conn->rollBack();
            $this->logError('Error al restablecer contraseña: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error al restablecer la contraseña'
            ];
        }
    }

    // =========================================================================
    // AUTENTICACIÓN
    // =========================================================================

    /**
     * Autentica un usuario
     * 
     * @param string $nombreUsuario Nombre de usuario
     * @param string $password Contraseña
     * @return array Resultado de la autenticación
     */
    public function authenticate($nombreUsuario, $password)
    {
        try {
            $nombreUsuario = $this->sanitizeInput($nombreUsuario);

            if (empty($nombreUsuario) || empty($password)) {
                return [
                    'success' => false,
                    'message' => 'Usuario y contraseña son obligatorios'
                ];
            }

            // Verificar bloqueo por intentos fallidos
            if ($this->isUserLocked($nombreUsuario)) {
                return [
                    'success' => false,
                    'message' => 'Usuario bloqueado temporalmente por múltiples intentos fallidos. Intente en 15 minutos.'
                ];
            }

            // Obtener usuario con contraseña
            // Convertir VARBINARY a VARCHAR para poder usar password_verify
            $sql = "
                SELECT 
                    IdUsuario, 
                    NombreUsuario, 
                    CAST(Password AS VARCHAR(255)) AS Password,
                    Nombre, 
                    Apellido, 
                    Activo
                FROM Usuario 
                WHERE NombreUsuario = :nombreUsuario
            ";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':nombreUsuario', $nombreUsuario);
            $stmt->execute();

            $user = $stmt->fetch();

            if (!$user) {
                $this->recordFailedAttempt($nombreUsuario);
                return [
                    'success' => false,
                    'message' => 'Usuario o contraseña incorrectos'
                ];
            }

            if (!$user['Activo']) {
                return [
                    'success' => false,
                    'message' => 'Usuario desactivado. Contacte al administrador.'
                ];
            }

            // Verificar contraseña
            $storedHash = $this->retrievePasswordFromStorage($user['Password']);
            
            if (!$this->verifyPassword($password, $storedHash)) {
                $this->recordFailedAttempt($nombreUsuario);
                return [
                    'success' => false,
                    'message' => 'Usuario o contraseña incorrectos'
                ];
            }

            // Limpiar intentos fallidos
            $this->clearFailedAttempts($nombreUsuario);

            // Obtener roles del usuario
            $roles = $this->getUserRoles($user['IdUsuario']);

            // Actualizar último acceso
            $this->updateLastAccess($user['IdUsuario']);

            unset($user['Password']); // No devolver la contraseña

            $this->logError("Login exitoso: {$nombreUsuario}", 'INFO');

            return [
                'success' => true,
                'message' => 'Autenticación exitosa',
                'data' => [
                    'user' => $user,
                    'roles' => $roles
                ]
            ];

        } catch (PDOException $e) {
            $this->logError('Error de autenticación: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Error al procesar la autenticación'
            ];
        }
    }

    /**
     * Verifica si un usuario está bloqueado por intentos fallidos
     * 
     * @param string $nombreUsuario Nombre de usuario
     * @return bool True si está bloqueado
     */
    private function isUserLocked($nombreUsuario)
    {
        $key = 'login_attempts_' . md5($nombreUsuario);
        
        if (isset($_SESSION[$key])) {
            $data = $_SESSION[$key];
            
            if ($data['count'] >= MAX_LOGIN_ATTEMPTS) {
                if (time() - $data['last_attempt'] < LOCKOUT_TIME) {
                    return true;
                }
                // Limpiar después del tiempo de bloqueo
                unset($_SESSION[$key]);
            }
        }
        
        return false;
    }

    /**
     * Registra un intento de login fallido
     * 
     * @param string $nombreUsuario Nombre de usuario
     */
    private function recordFailedAttempt($nombreUsuario)
    {
        $key = 'login_attempts_' . md5($nombreUsuario);
        
        if (!isset($_SESSION[$key])) {
            $_SESSION[$key] = ['count' => 0, 'last_attempt' => time()];
        }
        
        $_SESSION[$key]['count']++;
        $_SESSION[$key]['last_attempt'] = time();
    }

    /**
     * Limpia los intentos fallidos de un usuario
     * 
     * @param string $nombreUsuario Nombre de usuario
     */
    private function clearFailedAttempts($nombreUsuario)
    {
        $key = 'login_attempts_' . md5($nombreUsuario);
        unset($_SESSION[$key]);
    }

    /**
     * Actualiza la fecha de último acceso
     * 
     * @param int $idUsuario ID del usuario
     */
    private function updateLastAccess($idUsuario)
    {
        try {
            $sql = "UPDATE Usuario SET UltimoAcceso = GETDATE() WHERE IdUsuario = :idUsuario";
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(':idUsuario', intval($idUsuario), PDO::PARAM_INT);
            $stmt->execute();
        } catch (PDOException $e) {
            // No es crítico si falla
            $this->logError('Error al actualizar último acceso: ' . $e->getMessage(), 'WARNING');
        }
    }

    /**
     * Obtiene el último mensaje de error
     * 
     * @return string Mensaje de error
     */
    public function getLastError()
    {
        return $this->lastError;
    }
}

// =========================================================================
// MANEJADOR DE PETICIONES AJAX
// =========================================================================

/**
 * Procesa las peticiones AJAX
 */
function handleAjaxRequest()
{
    header('Content-Type: application/json; charset=utf-8');
    
    // Verificar que sea una petición AJAX
    if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
        // Permitir peticiones directas en desarrollo, pero loggear
        error_log('Petición no AJAX detectada');
    }

    $response = ['success' => false, 'message' => 'Acción no especificada'];

    try {
        // Obtener acción
        $action = isset($_POST['action']) ? $_POST['action'] : (isset($_GET['action']) ? $_GET['action'] : '');

        // Acciones que no requieren CSRF (solo lectura)
        $publicActions = ['getUsers', 'getRoles', 'getUser', 'getCsrfToken'];

        // Validar CSRF para acciones que modifican datos
        if (!in_array($action, $publicActions)) {
            $csrfToken = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
            if (!GestionUsuario::validateCsrfToken($csrfToken)) {
                $response = [
                    'success' => false,
                    'message' => 'Token de seguridad inválido. Por favor, recargue la página.'
                ];
                echo json_encode($response);
                return;
            }
        }

        $gestion = new GestionUsuario();

        switch ($action) {
            case 'getCsrfToken':
                $response = [
                    'success' => true,
                    'token' => GestionUsuario::generateCsrfToken()
                ];
                break;

            case 'getUsers':
                $filters = [
                    'estado' => isset($_GET['estado']) ? $_GET['estado'] : '',
                    'rol' => isset($_GET['rol']) ? $_GET['rol'] : '',
                    'busqueda' => isset($_GET['busqueda']) ? $_GET['busqueda'] : ''
                ];
                $page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
                $perPage = isset($_GET['perPage']) ? min(100, max(1, intval($_GET['perPage']))) : 10;
                
                $response = $gestion->getUsers($filters, $page, $perPage);
                break;

            case 'getUser':
                $idUsuario = isset($_GET['id']) ? intval($_GET['id']) : 0;
                $response = $gestion->getUserById($idUsuario);
                break;

            case 'getRoles':
                $response = $gestion->getAllRoles();
                break;

            case 'createUser':
                $userData = [
                    'nombreUsuario' => isset($_POST['nombreUsuario']) ? $_POST['nombreUsuario'] : '',
                    'nombre' => isset($_POST['nombre']) ? $_POST['nombre'] : '',
                    'apellido' => isset($_POST['apellido']) ? $_POST['apellido'] : '',
                    'rut' => isset($_POST['rut']) ? $_POST['rut'] : '',
                    'email' => isset($_POST['email']) ? $_POST['email'] : '',
                    'telefono' => isset($_POST['telefono']) ? $_POST['telefono'] : '',
                    'fechaNacimiento' => isset($_POST['fechaNacimiento']) ? $_POST['fechaNacimiento'] : '',
                    'password' => isset($_POST['password']) ? $_POST['password'] : '',
                    'activo' => isset($_POST['activo']) ? $_POST['activo'] : 1
                ];
                
                $roles = isset($_POST['roles']) ? (is_array($_POST['roles']) ? $_POST['roles'] : [$_POST['roles']]) : [];
                $rolPrincipal = isset($_POST['rolPrincipal']) ? intval($_POST['rolPrincipal']) : null;
                
                $response = $gestion->createUser($userData, $roles, $rolPrincipal);
                
                // Regenerar token CSRF después de crear usuario
                if ($response['success']) {
                    $response['newToken'] = GestionUsuario::regenerateCsrfToken();
                }
                break;

            case 'updateUser':
                $idUsuario = isset($_POST['idUsuario']) ? intval($_POST['idUsuario']) : 0;
                $userData = [
                    'nombreUsuario' => isset($_POST['nombreUsuario']) ? $_POST['nombreUsuario'] : '',
                    'nombre' => isset($_POST['nombre']) ? $_POST['nombre'] : '',
                    'apellido' => isset($_POST['apellido']) ? $_POST['apellido'] : '',
                    'rut' => isset($_POST['rut']) ? $_POST['rut'] : '',
                    'email' => isset($_POST['email']) ? $_POST['email'] : '',
                    'telefono' => isset($_POST['telefono']) ? $_POST['telefono'] : '',
                    'fechaNacimiento' => isset($_POST['fechaNacimiento']) ? $_POST['fechaNacimiento'] : '',
                    'password' => isset($_POST['password']) ? $_POST['password'] : '',
                    'activo' => isset($_POST['activo']) ? $_POST['activo'] : 1
                ];
                
                $roles = isset($_POST['roles']) ? (is_array($_POST['roles']) ? $_POST['roles'] : [$_POST['roles']]) : [];
                $rolPrincipal = isset($_POST['rolPrincipal']) ? intval($_POST['rolPrincipal']) : null;
                
                $response = $gestion->updateUser($idUsuario, $userData, $roles, $rolPrincipal);
                
                if ($response['success']) {
                    $response['newToken'] = GestionUsuario::regenerateCsrfToken();
                }
                break;

            case 'toggleStatus':
                $idUsuario = isset($_POST['idUsuario']) ? intval($_POST['idUsuario']) : 0;
                $activo = isset($_POST['activo']) ? intval($_POST['activo']) : 0;
                
                $response = $gestion->toggleUserStatus($idUsuario, $activo);
                
                if ($response['success']) {
                    $response['newToken'] = GestionUsuario::regenerateCsrfToken();
                }
                break;

            case 'resetPassword':
                $idUsuario = isset($_POST['idUsuario']) ? intval($_POST['idUsuario']) : 0;
                
                $response = $gestion->resetPassword($idUsuario);
                
                if ($response['success']) {
                    $response['newToken'] = GestionUsuario::regenerateCsrfToken();
                }
                break;

            case 'authenticate':
                $nombreUsuario = isset($_POST['nombreUsuario']) ? $_POST['nombreUsuario'] : '';
                $password = isset($_POST['password']) ? $_POST['password'] : '';
                
                $response = $gestion->authenticate($nombreUsuario, $password);
                break;

            case 'validateRut':
                $rut = isset($_POST['rut']) ? $_POST['rut'] : '';
                $isValid = $gestion->validateRut($rut);
                $response = [
                    'success' => true,
                    'valid' => $isValid,
                    'formatted' => $isValid ? $gestion->formatRut($rut) : '',
                    'message' => $isValid ? 'RUT válido' : 'RUT inválido'
                ];
                break;

            default:
                $response = [
                    'success' => false,
                    'message' => 'Acción no reconocida: ' . htmlspecialchars($action)
                ];
        }

    } catch (Exception $e) {
        error_log('Error en handleAjaxRequest: ' . $e->getMessage());
        $response = [
            'success' => false,
            'message' => 'Error interno del servidor'
        ];
    }

    echo json_encode($response, JSON_UNESCAPED_UNICODE);
}

// Ejecutar manejador si se accede directamente
if (basename($_SERVER['SCRIPT_FILENAME']) === 'GestionUsuario.php' && 
    (isset($_GET['action']) || isset($_POST['action']))) {
    handleAjaxRequest();
}
?>

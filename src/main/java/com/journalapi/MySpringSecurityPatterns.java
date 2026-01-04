/*@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth// this is whee we define who  can access what
                        .requestMatchers("/api/public/**").permitAll() ///// any url with that url is  permitted wiythout auth
                        .anyRequest().authenticated()//// any other reqques yeillm nr auth
                )
                .httpBasic(Customizer.withDefaults());//// enables auth

        return http.build();// use spring boot basic http
    }return http.build();
```

**`http.build()`** - Finalizes all the configuration and creates the SecurityFilterChain object

**`return`** - Returns the completed SecurityFilterChain to Spring

**What Spring does with it:**
- Uses this rulebook to configure security filters
- Installs it as THE security policy for your app
- Every request goes through these rules

**Real-world analogy:**
- You've filled out the security policy form
- Now you're submitting it to the security office
- They'll enforce these rules from now on

---

### **The Complete Flow of This Config:**
```
Spring Boot starts
    ↓
Sees @Configuration annotation
    ↓
Sees @EnableWebSecurity - activates security
    ↓
Calls securityFilterChain() method (because @Bean)
    ↓
Receives the configured SecurityFilterChain
    ↓
Installs these rules:
  - CSRF disabled
  - /api/public/** = no auth needed
  - Everything else = auth required
  - Use HTTP Basic Auth
    ↓
App is now running with security enabled


}///////queries database to verify users (changes if database changes)
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
                // Example 1: User EXISTS in database
User user = userRepository.findByUsername("testuser")  // Returns Optional with User
    .orElseThrow(() -> new UsernameNotFoundException(...));  // User exists, return it
// Result: user = User object from database

// Example 2: User DOESN'T EXIST
User user = userRepository.findByUsername("fakeuser")  // Returns empty Optional
    .orElseThrow(() -> new UsernameNotFoundException("User not found: fakeuser"));  // Throws exception
// Result: Exception thrown, authentication fails, 401 returned

// sending data back to sB
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),//gets username from User entitity pass to SB
                user.getPassword(),
                new ArrayList<>()
        );
    }
}
List<GrantedAuthority> authorities = new ArrayList<>();
authorities.add(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
// If user.getRole() = "ADMIN", this becomes "ROLE_ADMIN"
```

---

### **The Complete Flow Visualized:**
```
Spring Security: "Someone wants to log in as 'testuser' with password 'pass123'"
    ↓
Spring Security calls: loadUserByUsername("testuser")
    ↓
YOUR CODE: userRepository.findByUsername("testuser")
    ↓
MongoDB: db.users.findOne({ username: "testuser" })
    ↓
MongoDB returns: { username: "testuser", password: "pass123", email: "..." }
    ↓
YOUR CODE: Convert to Spring's User object
    ↓
YOUR CODE returns: User("testuser", "pass123", [])
    ↓
Spring Security receives the password: "pass123"
    ↓
Spring Security compares:
  - Password user sent: "pass123"
  - Password you returned: "pass123"
  - MATCH? YES
    ↓
Spring Security: "Authentication successful! Store 'testuser' in SecurityContext"
    ↓
Request proceeds to controller

// Add this helper method to your controller
private User getAuthenticatedUser() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String username = auth.getName();
    return userRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException(username));
}@PostMapping
public ResponseEntity<JournalDTO> create(@RequestBody CreateRequest request) {
    User currentUser = getAuthenticatedUser();  // ← Use this
    JournalDTO result = journalService.create(currentUser.getId(), request);
    return ResponseEntity.status(HttpStatus.CREATED).body(result);
}
// In your service layer
public JournalDTO update(String journalId, String userId, UpdateRequest request) {

    // Find resource
    Journal journal = journalRepository.findById(journalId)
            .orElseThrow(() -> new JournalNotFoundException(journalId));

    // Check ownership
    if (!journal.getUserId().equals(userId)) {
        throw new ForbiddenException("You don't own this journal");
    }

    // Proceed with update
    journal.setTitle(request.getTitle());
    journal.setContent(request.getContent());

    return mapper.toDTO(journalRepository.save(journal));
}

REQUEST FLOW:

1. Postman sent:
   GET /api/journals/test-auth
   Authorization: Basic testuser:password123

2. Spring Security intercepted:
   - Decoded credentials: username="testuser", password="password123"
   - Called CustomUserDetailsService.loadUserByUsername("testuser")

3. Your code queried database:
   - Found user in MongoDB
   - Returned password to Spring Security

4. Spring Security compared:
   - Client sent: "password123"
   - Database has: "password123"
   - MATCH ✅ → Authentication successful

5. Spring Security stored in SecurityContext:
   - principal: "testuser"
   - authenticated: true

6. Request reached your controller:
   - testAuthentication() method executed

7. getAuthenticatedUser() was called:
   - Read SecurityContext → got username "testuser"
   - Queried database for full User entity
   - Returned User with ID, email, etc.

8. Response built and returned:
   {
     "authenticatedUsername": "testuser",
     "authenticatedUserId": "6956d9fa76e32ce3c63ed98bb",
     "authenticatedEmail": "...",
     "message": "SecurityContext is working!"
   }

KEY PROOF:
✅ SecurityContext works - it stored authentica
Postman
  ↓ Authorization: Bearer <JWT>
JwtAuthenticationFilter
  ↓ validates token
  ↓ extracts username
  ↓ sets SecurityContext
Controller
  ↓ reads authenticated user
Service
  ↓ queries journals for that user
MongoDB
*/

/*
═══════════════════════════════════════════════════════════════════════════════
                    SPRING BOOT SECURITY - COMPLETE REFERENCE
                    (JWT + BCrypt + Roles + Refresh Tokens)
═══════════════════════════════════════════════════════════════════════════════

📋 TABLE OF CONTENTS:
1. Security Config (JWT + Role-Based)
2. CustomUserDetailsService (Bridge to Database)
3. JWT Service (Generate & Validate Tokens)
4. JWT Authentication Filter (Intercept & Validate)
5. Auth Controller (Login + Refresh + Logout)
6. Get Authenticated User Helper
7. Ownership Checks Pattern
8. DTOs (Request/Response)
9. Refresh Token Entity & Service
10. Complete Request Flow Diagrams
11. Testing Checklist

═══════════════════════════════════════════════════════════════════════════════
1️⃣ SECURITY CONFIG - JWT + ROLE-BASED ACCESS
═══════════════════════════════════════════════════════════════════════════════


@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // For @PreAuthorize annotations
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())  // Disable for stateless JWT
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // No sessions
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()     // Login, register, refresh
                        .requestMatchers("/api/public/**").permitAll()   // Public endpoints
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")  // Admin only
                        .anyRequest().authenticated()                    // Everything else needs auth
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);  // Add JWT filter

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();  // Use BCrypt for password hashing
    }
}

/*
KEY POINTS:
- SessionCreationPolicy.STATELESS = No sessions, JWT only
- jwtAuthFilter runs BEFORE Spring's username/password filter
- CSRF disabled (safe for stateless APIs)
- AuthenticationManager bean needed for login

═══════════════════════════════════════════════════════════════════════════════
2️⃣ CUSTOM USER DETAILS SERVICE - BRIDGE TO YOUR DATABASE
═══════════════════════════════════════════════════════════════════════════════

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        // Return Spring Security's User with authorities (roles)
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
        );
    }
}

/*
FLOW:
1. Spring Security calls this during authentication
2. You query YOUR database
3. Return UserDetails with username, password, roles
4. Spring Security compares passwords

═══════════════════════════════════════════════════════════════════════════════
3️⃣ JWT SERVICE - TOKEN GENERATION & VALIDATION
═══════════════════════════════════════════════════════════════════════════════


@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpiration;  // e.g., 3600000 (1 hour in ms)

    // Extract username from token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract any claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Generate token for user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", userDetails.getAuthorities().iterator().next().getAuthority());
        return buildToken(claims, userDetails, jwtExpiration);
    }

    // Build token with claims
    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Validate token
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getSignInKey())
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

/*
KEY METHODS:
- generateToken(): Creates JWT after login
- extractUsername(): Gets username from token
- isTokenValid(): Checks signature + expiration
- Token structure: Header.Payload.Signature (3 parts separated by dots)

application.properties:
jwt.secret=your-base64-encoded-secret-key-min-256-bits
jwt.expiration=3600000

═══════════════════════════════════════════════════════════════════════════════
4️⃣ JWT AUTHENTICATION FILTER - INTERCEPT ALL REQUESTS
═══════════════════════════════════════════════════════════════════════════════

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // Check if Authorization header exists and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);  // Remove "Bearer " prefix
        final String username = jwtService.extractUsername(jwt);

        // If username exists and user not already authenticated
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Validate token
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set authentication in SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}

/*
FLOW:
1. Extract "Bearer <token>" from Authorization header
2. Extract username from token
3. Load user from database
4. Validate token (signature + expiration)
5. If valid: Set authentication in SecurityContext
6. Continue to controller

═══════════════════════════════════════════════════════════════════════════════
5️⃣ AUTH CONTROLLER - LOGIN, REFRESH, LOGOUT


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    // LOGIN ENDPOINT
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        // Authenticate user (throws exception if wrong credentials)
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        // Load user details
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());

        // Generate access token
        String accessToken = jwtService.generateToken(userDetails);

        // Generate refresh token
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(request.getUsername());

        return ResponseEntity.ok(new LoginResponse(
                accessToken,
                refreshToken.getToken(),
                "Bearer",
                3600,  // Access token expires in 1 hour
                604800  // Refresh token expires in 7 days
        ));
    }

    // REFRESH TOKEN ENDPOINT
    @PostMapping("/refresh")
    public ResponseEntity<RefreshTokenResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        return refreshTokenService.findByToken(request.getRefreshToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUsername)
                .map(username -> {
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    String newAccessToken = jwtService.generateToken(userDetails);
                    return ResponseEntity.ok(new RefreshTokenResponse(newAccessToken, "Bearer", 3600));
                })
                .orElseThrow(() -> new TokenRefreshException("Invalid refresh token"));
    }

    // LOGOUT ENDPOINT
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody LogoutRequest request) {
        refreshTokenService.deleteByToken(request.getRefreshToken());
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}

/*
═══════════════════════════════════════════════════════════════════════════════
6️⃣ GET AUTHENTICATED USER HELPER - USE IN ALL CONTROLLERS
═══════════════════════════════════════════════════════════════════════════════


// Add this to your base controller or as a utility
private User getAuthenticatedUser() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String username = auth.getName();
    return userRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException(username));
}

// USAGE IN CONTROLLER
@PostMapping
public ResponseEntity<JournalDTO> create(@RequestBody @Valid CreateJournalRequest request) {
    User currentUser = getAuthenticatedUser();  // ✅ SECURE - from JWT
    JournalDTO journal = journalService.create(currentUser.getId(), request);
    return ResponseEntity.status(HttpStatus.CREATED).body(journal);
}

/*
NEVER DO THIS:
@PostMapping
public ResponseEntity<JournalDTO> create(
    @RequestParam String userId,  // ❌ INSECURE - client can fake this
    @RequestBody CreateJournalRequest request
)

═══════════════════════════════════════════════════════════════════════════════
7️⃣ OWNERSHIP CHECKS PATTERN - ALWAYS IN SERVICE LAYER
═══════════════════════════════════════════════════════════════════════════════

@Service
public class JournalService {

    // UPDATE - Check ownership
    public JournalDTO update(String journalId, String userId, UpdateJournalRequest request) {
        Journal journal = journalRepository.findById(journalId)
                .orElseThrow(() -> new JournalNotFoundException(journalId));

        // OWNERSHIP CHECK
        if (!journal.getUserId().equals(userId)) {
            throw new ForbiddenException("You don't own this journal");
        }

        journal.setTitle(request.getTitle());
        journal.setContent(request.getContent());
        return mapper.toDTO(journalRepository.save(journal));
    }

    // DELETE - Check ownership
    public void delete(String journalId, String userId) {
        Journal journal = journalRepository.findById(journalId)
                .orElseThrow(() -> new JournalNotFoundException(journalId));

        if (!journal.getUserId().equals(userId)) {
            throw new ForbiddenException("You don't own this journal");
        }

        journalRepository.delete(journal);
    }

    // CREATE - No check needed (user becomes owner)
    public JournalDTO create(String userId, CreateJournalRequest request) {
        Journal journal = new Journal();
        journal.setUserId(userId);  // Set authenticated user as owner
        journal.setTitle(request.getTitle());
        journal.setContent(request.getContent());
        return mapper.toDTO(journalRepository.save(journal));
    }
}

/*
═══════════════════════════════════════════════════════════════════════════════
8️⃣ DTOs - REQUEST & RESPONSE OBJECTS
═══════════════════════════════════════════════════════════════════════════════

// LOGIN REQUEST
@Data
public class LoginRequest {
    @NotBlank private String username;
    @NotBlank private String password;
}

// LOGIN RESPONSE
@Data
@AllArgsConstructor
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private String type;  // "Bearer"
    private long accessTokenExpiresIn;
    private long refreshTokenExpiresIn;
}

// REFRESH TOKEN REQUEST
@Data
public class RefreshTokenRequest {
    @NotBlank private String refreshToken;
}

// REFRESH TOKEN RESPONSE
@Data
@AllArgsConstructor
public class RefreshTokenResponse {
    private String accessToken;
    private String type;
    private long expiresIn;
}

/*
═══════════════════════════════════════════════════════════════════════════════
9️⃣ REFRESH TOKEN - ENTITY & SERVICE
═══════════════════════════════════════════════════════════════════════════════

@Document(collection = "refresh_tokens")
@Data
public class RefreshToken {
    @Id
    private String id;
    private String token;
    private String username;
    private Instant expiryDate;
}

@Service
public class RefreshTokenService {

    @Value("${jwt.refresh.expiration}")
    private long refreshTokenDuration;  // e.g., 604800000 (7 days)

    private final RefreshTokenRepository repository;

    public RefreshToken createRefreshToken(String username) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUsername(username);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDuration));
        return repository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return repository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            repository.delete(token);
            throw new TokenRefreshException("Refresh token expired");
        }
        return token;
    }

    public void deleteByToken(String token) {
        repository.findByToken(token).ifPresent(repository::delete);
    }
}

/*
═══════════════════════════════════════════════════════════════════════════════
🔟 COMPLETE REQUEST FLOW DIAGRAMS
═══════════════════════════════════════════════════════════════════════════════

📍 FLOW 1: LOGIN (First Time)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Client → POST /api/auth/login {username, password}
  ↓
AuthController.login()
  ↓
AuthenticationManager.authenticate()
  ↓
CustomUserDetailsService.loadUserByUsername()
  ↓
Query MongoDB for user
  ↓
Return UserDetails (username, password, roles)
  ↓
BCrypt.matches(sentPassword, dbPassword) → MATCH ✅
  ↓
Generate access token (JWT - expires 1 hour)
Generate refresh token (UUID - expires 7 days)
  ↓
Return: {accessToken, refreshToken, type: "Bearer", expiresIn}
  ↓
Client stores both tokens

📍 FLOW 2: API CALL WITH JWT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Client → GET /api/journals
Headers: Authorization: Bearer <accessToken>
  ↓
JwtAuthenticationFilter intercepts
  ↓
Extract token from header
  ↓
JwtService.extractUsername(token) → "testuser"
  ↓
JwtService.isTokenValid(token) → TRUE ✅
  ↓
Load UserDetails from database
  ↓
Set SecurityContext with authentication
  ↓
JournalController.getAll()
  ↓
getAuthenticatedUser() reads SecurityContext
  ↓
Extract username → Query DB → Get User entity
  ↓
Service.findByUserId(user.getId())
  ↓
Return journals → Response to client

📍 FLOW 3: TOKEN REFRESH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Access token expires (1 hour passed)
  ↓
Client → POST /api/auth/refresh {refreshToken}
  ↓
RefreshTokenService.findByToken()
  ↓
Verify token not expired
  ↓
Extract username from refresh token
  ↓
Generate NEW access token
  ↓
Return: {accessToken, type: "Bearer", expiresIn: 3600}
  ↓
Client updates stored access token
  ↓
Continue making API calls with new token

═══════════════════════════════════════════════════════════════════════════════
1️⃣1️⃣ TESTING CHECKLIST FOR NEW PROJECTS
═══════════════════════════════════════════════════════════════════════════════

✅ PHASE 1: REGISTRATION & LOGIN
□ Register new user → 201 Created
□ Login with correct credentials → 200 OK (receive tokens)
□ Login with wrong password → 401 Unauthorized
□ Login with non-existent user → 401 Unauthorized

✅ PHASE 2: JWT AUTHENTICATION
□ API call WITHOUT token → 401 Unauthorized
□ API call WITH valid token → 200 OK (data returned)
□ API call WITH expired token → 401 Unauthorized
□ API call WITH invalid token → 401 Unauthorized

✅ PHASE 3: OWNERSHIP
□ Create resource → 201 Created (user becomes owner)
□ Update OWN resource → 200 OK
□ Update SOMEONE ELSE'S resource → 403 Forbidden
□ Delete OWN resource → 204 No Content
□ Delete SOMEONE ELSE'S resource → 403 Forbidden

✅ PHASE 4: ROLES (if implemented)
□ USER access /api/admin/** → 403 Forbidden
□ ADMIN access /api/admin/** → 200 OK
□ Check JWT contains correct role claim

✅ PHASE 5: REFRESH TOKENS
□ Access token expired + valid refresh token → New access token
□ Expired refresh token → 401 (must re-login)
□ Logout → Refresh token deleted → Can't refresh anymore

═══════════════════════════════════════════════════════════════════════════════
📚 DEPENDENCIES (pom.xml)
═══════════════════════════════════════════════════════════════════════════════


<dependencies>
    <!-- Spring Boot Starters -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-mongodb</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>

    <!-- JWT -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>

    <!-- Lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
</dependencies>

/*
═══════════════════════════════════════════════════════════════════════════════
⚙️ APPLICATION.PROPERTIES TEMPLATE
═══════════════════════════════════════════════════════════════════════════════

        # MongoDB
spring.data.mongodb.uri=mongodb+srv://user:pass@cluster.mongodb.net/dbname

        # JWT
jwt.secret=your-base64-secret-key-min-256-bits-CHANGE-IN-PRODUCTION
jwt.expiration=3600000
jwt.refresh.expiration=604800000

        # Server
server.port=8080

/*
═══════════════════════════════════════════════════════════════════════════════
🎯 QUICK START CHECKLIST FOR NEW PROJECT
═══════════════════════════════════════════════════════════════════════════════

1. Add dependencies to pom.xml
2. Create User entity with username, password, email, role fields
3. Create UserRepository extends MongoRepository
4. Copy SecurityConfig (this file)
5. Copy CustomUserDetailsService
6. Copy JwtService
7. Copy JwtAuthenticationFilter
8. Copy AuthController
9. Create DTOs (LoginRequest, LoginResponse, etc.)
10. Add jwt.secret and jwt.expiration to application.properties
11. Create RefreshToken entity and RefreshTokenService (optional)
12. Test with Postman following testing checklist above

═══════════════════════════════════════════════════════════════════════════════
🚨 COMMON PITFALLS TO AVOID
═══════════════════════════════════════════════════════════════════════════════

❌ Trusting @RequestParam userId from client
❌ Storing plain text passwords (always use BCrypt)
❌ Not checking token expiration
❌ Skipping ownership checks in service layer
❌ Returning entity objects instead of DTOs (exposes passwords)
❌ Using Basic Auth in production (use JWT)
❌ Not validating input with @Valid
❌ Committing secrets to Git (use environment variables)
❌ Enabling CSRF for stateless JWT APIs
❌ Not implementing refresh tokens (poor UX - user logged out every hour)

═══════════════════════════════════════════════════════════════════════════════
                            END OF REFERENCE GUIDE
═══════════════════════════════════════════════════════════════════════════════
*/
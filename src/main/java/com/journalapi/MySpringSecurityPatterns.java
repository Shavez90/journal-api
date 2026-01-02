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
✅ SecurityContext works - it stored authentica*/

# Spring security JWT authentication - implementation guide

This detailed guide explains how this project implements JWT-based authentication using Spring Security 6, designed as a learning resource rather than just documentation.

## Detailed Implementation Breakdown

### 1. User Model (`User.java`)

The `User` entity is the foundation of the security model, implementing Spring Security's `UserDetails` interface:

```java
public class User implements UserDetails {
    // Fields: id, username, email, password
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("USER")); 
        // All users have the same role in this sample
    }
    
    @Override
    public String getUsername() {
        return email; // Using email as the username identifier
    }
    
    // Other UserDetails methods all return true for simplicity
}
```

**Key points:**
- Spring Security identifies users by whatever `getUsername()` returns (email in this case)
- The `getAuthorities()` method provides roles/permissions for authorization decisions
- This implementation simplifies account state by having all accounts always active

### 2. JWT Service (`JwtService.java`)

This service handles all JWT operations using the `jjwt` library:

```java
@Service
public class JwtService {
    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    
    // Token operations
}
```

**Key methods:**

1. **Token Generation**
   ```java
   public String generateToken(UserDetails userDetails) {
       return Jwts.builder()
               .setSubject(userDetails.getUsername()) // Sets email as subject
               .setIssuedAt(new Date())               // When token was issued
               .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // 24 minutes expiry
               .signWith(getSignInKey(), SignatureAlgorithm.HS256)
               .compact();
   }
   ```

2. **Token Validation**
   ```java
   public boolean isTokenValid(String token, UserDetails userDetails) {
       final String username = extractUsername(token);
       return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
   }
   ```

3. **Claims Extraction**
   ```java
   public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
       final Claims claims = extractAllClaims(token);
       return claimsResolver.apply(claims);
   }
   ```

**Key points:**
- JWT tokens are self-contained (stateless) with all necessary user info
- The server only needs to verify signature and expiration
- The signing key (SECRET_KEY) should be secured in production environments

### 3. Authentication Filter (`JwtAuthFilter.java`)

This filter intercepts all requests to validate JWT tokens:

```java
@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    // Execution flow of filter
}
```

**Filter execution flow:**

1. **Header Extraction**
   ```java
   final String authHeader = request.getHeader("Authorization");
   if (authHeader == null || !authHeader.startsWith("Bearer ")) {
       filterChain.doFilter(request, response); // Proceed without authentication
       return;
   }
   ```

2. **JWT Processing**
   ```java
   jwt = authHeader.substring(7); // Remove "Bearer " prefix
   userEmail = jwtService.extractUsername(jwt);
   ```

3. **Authentication Setup**
   ```java
   if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
       UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
       
       if (jwtService.isTokenValid(jwt, userDetails)) {
           UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                   userDetails, null, userDetails.getAuthorities());
                   
           authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
           SecurityContextHolder.getContext().setAuthentication(authToken);
       }
   }
   ```

**Key points:**
- The filter is applied to every request that passes through the security chain
- It only processes requests with "Bearer" tokens
- When a valid token is found, it creates an Authentication object in the SecurityContext
- The filter doesn't block invalid tokens - it simply doesn't set up authentication

### 4. Security Configuration (`SecurityConfig.java`)

This class configures Spring Security's behavior:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    // Security settings
}
```

**Key configurations:**

1. **Security Filter Chain**
   ```java
   @Bean
   public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http
               .csrf(AbstractHttpConfigurer::disable) // Disabled for REST APIs
               .authorizeHttpRequests(auth -> auth
                       .requestMatchers(
                               "/api/auth/**",       // Auth endpoints
                               "/swagger-ui/**",    // API documentation
                               "/v3/api-docs/**"
                       ).permitAll()
                       .anyRequest().authenticated() // All other endpoints require auth
               )
               .sessionManagement(session -> session
                       .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // No sessions
               )
               .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
   }
   ```

2. **Password Encoder and Authentication Manager**
   ```java
   @Bean
   public PasswordEncoder passwordEncoder() {
       return new BCryptPasswordEncoder();
   }

   @Bean
   public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
       return config.getAuthenticationManager();
   }
   ```

**Key points:**
- `SessionCreationPolicy.STATELESS` tells Spring not to create HTTP sessions
- The JWT filter is added before `UsernamePasswordAuthenticationFilter` to process tokens before standard form logins
- Public endpoints are explicitly configured with `permitAll()`
- BCrypt is used for password hashing

### 5. Authentication Service (`AuthService.java`)

This service handles user registration and login:

```java
@Service
public class AuthService {
    // Authentication operations
}
```

**Key operations:**

1. **User Registration**
   ```java
   public AuthResponse register(RegisterRequest request) {
       var user = User.builder()
               .username(request.getUsername())
               .email(request.getEmail())
               .password(passwordEncoder.encode(request.getPassword())) // Password hashing
               .build();
       userRepository.save(user);
       var jwtToken = jwtService.generateToken(user);
       return AuthResponse.builder().token(jwtToken).build();
   }
   ```

2. **User Authentication**
   ```java
   public AuthResponse authenticate(AuthRequest request) {
       authenticationManager.authenticate(
               new UsernamePasswordAuthenticationToken(
                       request.getEmail(),
                       request.getPassword()
               )
       );
       var user = userRepository.findByEmail(request.getEmail())
               .orElseThrow();
       var jwtToken = jwtService.generateToken(user);
       return AuthResponse.builder().token(jwtToken).build();
   }
   ```

**Key points:**
- The `authenticationManager.authenticate()` call validates credentials
- If authentication fails, it throws an exception that Spring Security translates to an HTTP 401
- Successful authentication generates and returns a JWT token
- Password encoding happens during registration

### 6. UserDetailsService Implementation (`UserDetailsServiceImpl.java`)

This service loads user data for Spring Security:

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
```

**Key points:**
- Spring Security uses this service to load users during authentication
- The "username" parameter is actually the email in this implementation
- Returns a User object that implements the UserDetails interface

## Authentication Sequence

1. **Registration Flow**
   - Client sends username, email, password to `/api/auth/register`
   - Password is hashed with BCrypt
   - User is saved to database
   - JWT token is generated and returned

2. **Login Flow**
   - Client sends email, password to `/api/auth/authenticate`
   - AuthenticationManager validates credentials
   - JWT token is generated and returned

3. **Protected Endpoint Access Flow**
   - Client includes JWT in Authorization header
   - JwtAuthFilter extracts and validates the token
   - On valid token, user details are loaded and Authentication is set
   - Request proceeds to controller

## Security Considerations

1. **JWT Secret Key**: In production, the secret key should be externalized to environment variables or a secure vault.

2. **Token Expiration**: This implementation uses a short (24 minutes) expiration time. Adjust based on security requirements.

3. **Error Handling**: This sample has minimal error handling. Production code should include proper exception handling.

4. **Password Strength**: No password complexity rules are enforced in this sample.

5. **CSRF Protection**: CSRF protection is disabled as it's typically not needed for token-based APIs. If your app serves browser clients, consider enabling it.

## Implementation Extensions

To extend this sample, consider:

1. Adding refresh tokens
2. Implementing role-based access control
3. Adding token blacklisting
4. Enhancing JWT with additional claims

This implementation provides a foundation for secure, stateless authentication that can be extended for more complex applications.

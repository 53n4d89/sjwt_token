# sjwt_token

While I was working on a small application for cybersecurity purposes, I recognized the need to enhance the security of JSON Web Tokens (JWTs). As per the standards, if a JWT is stolen or compromised, the attacker gains unrestricted access to the associated account. However, I decided to implement a small but significant improvement to mitigate this risk.

By incorporating a unique identifier (unique id) into the JWT generation process, the level of difficulty for an attacker significantly increases. In the event of a stolen JWT, the attacker would not only require the token itself but would also need to discover additional personal information associated with the unique id.(Doesn't have anything with db). This additional layer of security adds an extra barrier, making unauthorized access more challenging and providing an additional safeguard against potential threats. By implementing this improvement, I aimed to create a more robust and secure authentication system, bolstering the overall protection of user accounts and sensitive data. Safeguarding against unauthorized access is a fundamental aspect of any cybersecurity strategy, and this small enhancement serves as a valuable step towards achieving that goal.


# License
jswt_token is made with hearts by [Senad Cavkusic](https://linkedin.com/in/senad-cavkusic) and it is released under the MIT license.

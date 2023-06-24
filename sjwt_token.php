<?php

    protected function generateToken($user) {
        $header = $this->base64UrlEncode(json_encode([
            'alg' => 'HS256',
            'typ' => 'JWT'
        ]));

        $payload = $this->base64UrlEncode(json_encode([
            'iss' => 'senad_cavkusic',
            'aud' => '.sarajevoweb.com',
            'iat' => time(),
            'exp' => time() + 3600,
            'idv' => $user['id'],
            'ipv' => $this->grabUserIpAddress()
        ]));

        $dataToSign = "$header.$payload";
        $signature = $this->base64UrlEncode(hash_hmac('sha256', $dataToSign, $this->jwtSecretKey, true));

        return "$dataToSign.$signature";
    }

    protected function getUniqueBrowserId() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'];

        // Check for shared internet/ISP IP
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddress = $_SERVER['HTTP_CLIENT_IP'];
        }

        // Check for IPs passing through proxies
        elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // We need to check if it's a list of IP addresses
            $ipList = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            // We'll take the last IP in the list
            $ipAddress = trim(end($ipList));
        }

        // If not, we use the sent IP address (most probably it's a direct access from the user)
        else {
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        }

        // Remove the dots from the IP address
        $ipAddress = str_replace('.', '', $ipAddress);

        // Convert to base64
        $uniqueId = hash('sha256', $userAgent . $ipAddress);

        return $uniqueId;
    }

    public function validateToken($token) {
        $tokenParts = explode('.', $token);
        if (count($tokenParts) != 3) {
            throw new Exception('Invalid token format');
        }

        $headerBase64 = $tokenParts[0];
        $payloadBase64 = $tokenParts[1];
        $signatureBase64 = $tokenParts[2];

        $header = json_decode($this->base64UrlDecode($headerBase64), true);
        $payload = json_decode($this->base64UrlDecode($payloadBase64), true);
        $signature = $this->base64UrlDecode($signatureBase64);

        // Verify the header
        if (!isset($header['alg']) || $header['alg'] !== 'HS256') {
            throw new Exception('Unexpected or missing algorithm in token header');
        }

        // Verify the signature
        $expectedSignature = hash_hmac('sha256', "$headerBase64.$payloadBase64", $this->jwtSecretKey, true);
        if (!hash_equals($expectedSignature, $signature)) {
            throw new Exception('Invalid token signature');
        }

        // Verify the issuer
        if (!isset($payload['iss']) || $payload['iss'] !== 'senad_cavkusic') {
            throw new Exception('Invalid token issuer');
        }

        // Verify the token hasn't expired
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new Exception('Token has expired');
        }

        // Verify the IP address
        $userId = isset($payload['idv']) ? $payload['idv'] : null;
        $userIP = $this->grabUserIpAddress();
        $storedIP = isset($payload['ipv']) ? $payload['ipv'] : null;

        if($storedIP !== $userIP){
            throw new Exception('Invalid IP address');
        }

        return $userId;
    }

    protected function base64UrlEncode($data) {
        $encoded = base64_encode($data);
        $encoded = str_replace(['+', '/', '='], ['-', '_', ''], $encoded);

        return $encoded;
    }

    protected function base64UrlDecode($data) {
        $padded = str_pad($data, strlen($data) % 4, '=', STR_PAD_RIGHT);
        return base64_decode(strtr($padded, '-_', '+/'));
    }

}

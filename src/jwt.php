<?php

namespace Blurpa\EasyJWT;

abstract class JWT
{
    /**
     * @param array $payload
     * @param string $key
     * @param string $algorithm
     *
     * @return string
     */
    public static function encode($payload, $key, $algorithm = 'SHA256')
    {
        if (!is_array($payload)) {
            throw new \InvalidArgumentException('Expected payload to be an array.');
        }

        $header = array('alg' => $algorithm,
                        'typ' => 'JWT');

        $jwtSegments = array();
        $jwtSegments[0] = self::uriSafeBase64Encode(json_encode($header));
        $jwtSegments[1] = self::uriSafeBase64Encode(json_encode($payload));

        $signature = self::secureHash(implode('.', $jwtSegments), $key, $algorithm);
        $jwtSegments[2] = self::uriSafeBase64Encode($signature);

        return implode('.', $jwtSegments);
    }

    /**
     * @param string $token
     * @param string $key
     * @param string $algorithm
     *
     * @return array
     *
     * @throws Exception\SignatureMismatchException
     */
    public static function decode($token, $key, $algorithm = 'SHA256')
    {
        $jwt = explode('.', $token);

        $signatureInput = $jwt[0] . '.' . $jwt[1];
        $signature = self::secureHash($signatureInput, $key, $algorithm);

        if (!hash_equals($signature, self::uriSafeBase64Decode($jwt[2]))) {
            throw new Exception\SignatureMismatchException();
        }

        return json_decode(self::uriSafeBase64Decode($jwt[1]), true);
    }

    /**
     * @param string $input
     *
     * @return string
     */
    public static function uriSafeBase64Encode($input)
    {
        return strtr(base64_encode($input), '+/=', '-_,');
    }

    /**
     * @param string $input
     *
     * @return string
     */
    public static function uriSafeBase64Decode($input)
    {
        return base64_decode(strtr($input, '-_,', '+/='));
    }

    /**
     * @param string $message
     * @param string $key
     * @param string $algorithm
     *
     * @return string
     */
    public static function secureHash($message, $key, $algorithm)
    {
        return hash_hmac($algorithm, $message, $key, true);
    }
}

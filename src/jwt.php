<?php

namespace Blurpa\EasyJWT;

class JWT
{
    /**
     * @var Encoder
     */
    private $encoder;

    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var array
     */
    private $payloadData = array();

    /**
     * @var string
     */
    private $jsonWebToken;

    /**
     * @var bool
     */
    private $tokenValidated;

    /**
     * JWT constructor.
     *
     * Optionally sets the secret key and algorithm to be used. The hashing algorithm defaults to SHA256 but can be
     * changed with the setAlg() method.
     *
     * @param array $options
     *
     * @param Encoder $encoder
     */
    public function __construct(Encoder $encoder, array $options = array())
    {
        $this->encoder = $encoder;

        if (isset($options['key'])) {
            $this->key = $options['key'];
        }

        if (isset($options['alg'])) {
            $this->algorithm = $options['alg'];
        } else {
            $this->algorithm = 'SHA256';  //HS256
        }
    }

    /**
     * @param $key
     *
     * @return JWT $this
     */
    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }

    /**
     * @param $algorithm
     *
     * @return JWT $this
     */
    public function setAlg($algorithm)
    {
        $this->algorithm = $algorithm;

        return $this;
    }

    /**
     * @param $payload
     *
     * @return JWT $this
     */
    public function setPayload($payload)
    {
        if (!is_array($payload)) {
            throw new \InvalidArgumentException('Expected payload to be an array.');
        }
        $this->payloadData = $payload;

        return $this;
    }

    /**
     * @return JWT $this
     */
    public function sign()
    {
        if (empty($this->key)) {
            throw new \InvalidArgumentException('Secret key needs to be used.');
        }

        $headerData = array('typ'=>'JWT', 'alg'=>$this->algorithm);
        $jwtSegment[0] = $this->encoder->encodeData($headerData);
        $jwtSegment[1] = $this->encoder->encodeData($this->payloadData);

        $signature = $this->secureHash(implode('.', $jwtSegment), $this->key, $this->algorithm);
        $jwtSegment[2] = $this->encoder->encode($signature);

        $this->jsonWebToken = implode('.', $jwtSegment);

        return $this;
    }

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->jsonWebToken;
    }

    /**
     * @param string $jsonWebToken
     *
     * @return JWT $this
     */
    public function load($jsonWebToken)
    {
        $this->jsonWebToken = $jsonWebToken;

        $jwtSegment = explode('.', $this->jsonWebToken);

        $signatureInput = $jwtSegment[0] . '.' . $jwtSegment[1];
        $signature = $this->secureHash($signatureInput, $this->key, $this->algorithm);

        $this->tokenValidated = hash_equals($signature, $this->encoder->decode($jwtSegment[2]));

        $this->payloadData = ($this->tokenValidated) ? $this->encoder->decodeData($jwtSegment[1]) : array();

        return $this;
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        return $this->tokenValidated;
    }

    /**
     * @return array
     */
    public function getPayload()
    {
        return $this->payloadData;
    }

    /**
     * @param string $data
     * @param string $key
     * @param string $algorithm
     *
     * @return string
     */
    private function secureHash($data, $key, $algorithm)
    {
        return hash_hmac($algorithm, $data, $key, true);
    }
}

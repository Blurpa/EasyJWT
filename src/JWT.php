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
        $this->tokenValidated = false;
        $this->encoder = $encoder;

        if (isset($options['key'])) {
            $this->key = $options['key'];
        }

        if (isset($options['alg'])) {
            $this->algorithm = $options['alg'];
        } else {
            $this->algorithm = 'SHA256';  //RS256
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

        $signature = $this->secureHash(implode('.', $jwtSegment));
        $jwtSegment[2] = $this->encoder->encode($signature);

        $this->jsonWebToken = implode('.', $jwtSegment);
        $this->tokenValidated = true;

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

        if (count($jwtSegment) != 3) {
            $this->payloadData = array();
            $this->tokenValidated = false;
            return $this;
        }

        $createdSignature = $this->secureHash($jwtSegment[0] . '.' . $jwtSegment[1]);
        $providedSignature = $this->encoder->decode($jwtSegment[2]);

        if($this->verifyHash($createdSignature, $providedSignature)) {
            $this->payloadData = $this->encoder->decodeData($jwtSegment[1]);
            $this->tokenValidated = true;
        } else {
            $this->payloadData = array();
            $this->tokenValidated = false;
        }

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
     *
     * @return string
     */
    private function secureHash($data)
    {
        return hash_hmac($this->algorithm, $data, $this->key, true);
    }

    /**
     * @param string $createdSignature
     * @param string $providedSignature
     *
     * @return bool
     */
    private function verifyHash($createdSignature, $providedSignature)
    {
        return hash_equals($createdSignature, $providedSignature);
    }
}

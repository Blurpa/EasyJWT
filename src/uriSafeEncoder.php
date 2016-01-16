<?php

namespace Blurpa\EasyJWT;

class uriSafeEncoder implements Encoder
{
    public function encode($input)
    {
        return strtr(base64_encode($input), '+/=', '-_,');
    }

    public function decode($input)
    {
        return base64_decode(strtr($input, '-_,', '+/='));
    }

    public function encodeWithData($input)
    {
        return $this->encode(json_encode($input));
    }

    public function decodeWithData($input)
    {
        return json_decode($this->decode($input), true);
    }
}

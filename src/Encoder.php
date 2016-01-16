<?php

namespace Blurpa\EasyJWT;

interface Encoder
{
    /**
     * @param string $input
     *
     * @return string
     */
    public function encode($input);

    /**
     * @param string $input
     *
     * @return array
     */
    public function decode($input);

    /**
     * @param string $input
     *
     * @return string
     */
    public function encodeData($input);

    /**
     * @param string $input
     *
     * @return array
     */
    public function decodeData($input);
}

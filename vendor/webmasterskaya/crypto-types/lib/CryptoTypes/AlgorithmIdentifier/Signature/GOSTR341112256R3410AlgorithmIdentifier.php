<?php

declare(strict_types = 1);

namespace Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature;

/**
 * RSA with GOSTR3411_2012_256 signature algorithm identifier.
 *
 * @see https://tools.ietf.org/html/rfc7836#section-4
 */
class GOSTR341112256R3410AlgorithmIdentifier extends RFC7836RSASignatureAlgorithmIdentifier
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->_oid = self::OID_CP_GOST_R3411_12_256_R3410;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'GOST_R3411_12_256_R3410';
    }
}

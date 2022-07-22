<?php

declare(strict_types = 1);

namespace Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature;

use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\AlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Feature\SignatureAlgorithmIdentifier;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/**
 * Base class for signature algorithms employing RSASSA.
 */
abstract class RSASignatureAlgorithmIdentifier extends SpecificAlgorithmIdentifier implements SignatureAlgorithmIdentifier
{
    /**
     * {@inheritdoc}
     */
    public function supportsKeyAlgorithm(AlgorithmIdentifier $algo): bool
    {
        return self::OID_RSA_ENCRYPTION === $algo->oid();
    }
}

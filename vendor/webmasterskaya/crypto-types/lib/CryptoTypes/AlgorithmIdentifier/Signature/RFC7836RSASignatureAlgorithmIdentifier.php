<?php

declare(strict_types = 1);

namespace Webmasterskaya\CryptoTypes\AlgorithmIdentifier\Signature;

use Sop\ASN1\Element;
use Sop\ASN1\Type\Primitive\NullType;
use Sop\ASN1\Type\UnspecifiedType;
use Webmasterskaya\CryptoTypes\AlgorithmIdentifier\SpecificAlgorithmIdentifier;

/*
From RFC 7836.  Guidelines on the Cryptographic Algorithms to
Accompany the Usage of Standards GOST R 34.10-2012 and GOST R 34.11-2012

   When any of these four object identifiers appears within an
   AlgorithmIdentifier, the parameters MUST be NULL.  Implementations
   MUST accept the parameters being absent as well as present.
*/

/**
 * Base class for GOST signature algorithms specified in RFC 7836.
 *
 * @see https://tools.ietf.org/html/rfc7836#section-4
 */
abstract class RFC7836RSASignatureAlgorithmIdentifier extends RSASignatureAlgorithmIdentifier
{
    /**
     * Parameters.
     *
     * @var null|Element
     */
    protected $_params;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_params = new NullType();
    }

    /**
     * {@inheritdoc}
     *
     * @return self
     */
    public static function fromASN1Params(
        ?UnspecifiedType $params = null): SpecificAlgorithmIdentifier
    {
        $obj = new static();
        // store parameters so re-encoding doesn't change
        if (isset($params)) {
            $obj->_params = $params->asElement();
        }
        return $obj;
    }

    /**
     * {@inheritdoc}
     */
    protected function _paramsASN1(): ?Element
    {
        return $this->_params;
    }
}

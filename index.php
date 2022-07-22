<?php

use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Webmasterskaya\X509\Certificate\Certificate;

require_once __DIR__ . './vendor/autoload.php';
$file_name = $_REQUEST['url'];

$fileURL=$file_name;
$headers = get_headers($fileURL, 1);

$lastModifiedDate = "";

if ( $headers && (strpos($headers[0],'200') !== FALSE) ) {
    $time=strtotime($headers['Last-Modified']);
    $lastModifiedDate=date("d-m-Y H:i:s", $time);
}

$content = file_get_contents($file_name);

$regexp = '#ByteRange\[\s*(\d+) (\d+) (\d+)#'; // subexpressions are used to extract b and c

$result = [];
preg_match_all($regexp, $content, $result);

if (isset($result[2]) && isset($result[3]) && isset($result[2][0])
    && isset($result[3][0])
) {
    $start = $result[2][0];
    $end   = $result[3][0];
    if ($stream = fopen($file_name, 'rb')) {
        $signature = stream_get_contents(
            $stream, $end - $start - 2, $start + 1
        ); // because we need to exclude < and > from start and end

        fclose($stream);
    }

    if (!empty($signature)) {
        $binary = hex2bin($signature);

        $seq         = Sequence::fromDER($binary);
        $signed_data = $seq->getTagged(0)->asExplicit()->asSequence();
        $ecac        = $signed_data->getTagged(0)->asImplicit(Element::TYPE_SET)
            ->asSet();
        /** @var Sop\ASN1\Type\UnspecifiedType $ecoc */
        $ecoc = $ecac->at($ecac->count() - 1);
        $cert = Certificate::fromASN1($ecoc->asSequence());

        $sig_array=[];

        foreach ($cert->tbsCertificate()->subject()->all() as $attr) {
            /** @var Webmasterskaya\X501\ASN1\AttributeTypeAndValue $atv */
            $atv = $attr->getIterator()->current();
            $sig_array[$atv->type()->typeName()] = $atv->value()->stringValue();
        }

//        var_dump($cert->tbsCertificate());
            echo 'Директор: '.$sig_array['sn'].' '.$sig_array['givenName'] . PHP_EOL;
            echo 'Подписанно: '. $lastModifiedDate . PHP_EOL;
            echo 'Серийный номер: '.$cert->tbsCertificate()->serialNumber() . PHP_EOL;
//        echo $sig_array['title'].':'.$sig_array['o']
    }
}
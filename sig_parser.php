<?php
/*
Plugin Name: sig parser
Description: get sig info from pdf
Version: 1.0
*/
use Sop\ASN1\Element;
use Sop\ASN1\Type\Constructed\Sequence;
use Webmasterskaya\X509\Certificate\Certificate;

require_once __DIR__ . '/vendor/autoload.php';


class sigParserPlugin
{
    public function __construct(){
        $this->register_hooks();
        $this->register_shortcodes();
        $this->disableGutenberg();
    }

    private function register_shortcodes(){
        add_shortcode( 'sig_pdf', array($this, 'sig_pdf_func') );
    }
    private function register_hooks() {
        add_action('admin_head', array($this,'true_add_mce_button'));

    }

    private function disableGutenberg(){
        if( 'disable_gutenberg' ){
            remove_theme_support( 'core-block-patterns' ); // WP 5.5

            add_filter( 'use_block_editor_for_post_type', '__return_false', 100 );

            // отключим подключение базовых css стилей для блоков
            // ВАЖНО! когда выйдут виджеты на блоках или что-то еще, эту строку нужно будет комментировать
            remove_action( 'wp_enqueue_scripts', 'wp_common_block_scripts_and_styles' );

            // Move the Privacy Policy help notice back under the title field.
            add_action( 'admin_init', function(){
                remove_action( 'admin_notices', [ 'WP_Privacy_Policy_Content', 'notice' ] );
                add_action( 'edit_form_after_title', [ 'WP_Privacy_Policy_Content', 'notice' ] );
            } );
        }
    }

    public function true_add_mce_button() {
        // проверяем права пользователя - может ли он редактировать посты и страницы
        if ( !current_user_can( 'edit_posts' ) && !current_user_can( 'edit_pages' ) ) {
            return; // если не может, то и кнопка ему не понадобится, в этом случае выходим из функции
        }
        // проверяем, включен ли визуальный редактор у пользователя в настройках (если нет, то и кнопку подключать незачем)
        if ( 'true' == get_user_option( 'rich_editing' ) ) {
            add_filter( 'mce_external_plugins', array($this,'true_add_tinymce_script') );
            add_filter( 'mce_buttons', array($this,'true_register_mce_button') );
        }
    }

    // В этом функции указываем ссылку на JavaScript-файл кнопки
    public function true_add_tinymce_script( $plugin_array ) {
        $plugin_array['true_mce_button'] =  plugin_dir_url('sig_parcer') .'sig_parcer/js/true_button.js'; // true_mce_button - идентификатор кнопки
        return $plugin_array;
    }

    // Регистрируем кнопку в редакторе
    public function true_register_mce_button( $buttons ) {
        array_push( $buttons, 'true_mce_button' ); // true_mce_button - идентификатор кнопки
        return $buttons;
    }


    public function sig_pdf_func($atts){
        return '<img title="'.$this->get_sig_info($atts['url']).'" src="'.plugin_dir_url(__FILE__).'/img/ECP.png"><a href="'.$atts['url'].'">'.$atts['title'].'</a>';
    }

    protected function get_sig_info($path=null){

        $result = '';

        if (is_null($path)){
            return $result;
        }

        $file_name = $path;

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
                $name = '';

            if (!empty($sig_array['sn'])){
                $name = $sig_array['sn'].' '.$sig_array['givenName'];
            }else{
                $name = $sig_array['cn'];
            }


                $result = 'Директор: '. $name . PHP_EOL.
                        'Подписанно: '. $lastModifiedDate . PHP_EOL.
                        'Серийный номер: '.$cert->tbsCertificate()->serialNumber() . PHP_EOL;
//        echo $sig_array['title'].':'.$sig_array['o']
            }
        }
//        $result = json_encode($sig_array,JSON_UNESCAPED_UNICODE);
        return $result;
    }
}

new sigParserPlugin();
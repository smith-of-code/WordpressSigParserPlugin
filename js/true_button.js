(function() {
	tinymce.PluginManager.add('true_mce_button', function( editor, url ) { // true_mce_button - ID кнопки
		editor.addButton('true_mce_button', {  // true_mce_button - ID кнопки, везде должен быть одинаковым
			text: 'ЭЦП ФАЙЛ', // текст кнопки, если вы хотите, чтобы ваша кнопка содержала только иконку, удалите эту строку
			title: 'Вставить шорткод [sig_pdf]', // всплывающая подсказка
			icon: false, // тут можно указать любую из существующих векторных иконок в TinyMCE либо собственный CSS-класс
			
				onclick: function() {
								editor.windowManager.open( {
									title: 'Задайте параметры',
									body: [
										{
											type: 'textbox', // тип textbox = текстовое поле
											name: 'url', // ID, будет использоваться ниже
											label: 'url', // лейбл
											value: '' // значение по умолчанию
										},
										{
											type: 'textbox', // тип textbox = текстовое поле
											name: 'title',
											label: 'Отображаемое название',
											value: ''
										}
									],
									onsubmit: function( e ) { // это будет происходить после заполнения полей и нажатии кнопки отправки
										editor.insertContent( '[sig_pdf url="' + e.data.url + '" title="' + e.data.title + '"]');
									}
								});
							}
			
		});
	});
})();
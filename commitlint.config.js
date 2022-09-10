module.exports = {
	parserPreset: 'conventional-changelog-conventionalcommits',
	rules: {
		'body-leading-blank': [1, 'always'],
// disable this one until we find a way for URLs to be allowed:
//		'body-max-line-length': [2, 'always', 64],
		'footer-leading-blank': [1, 'always'],
		'footer-max-line-length': [2, 'always', 150],
		'header-max-length': [2, 'always', 50],
		'subject-full-stop': [2, 'never', '.'],
		'type-empty': [1, 'never'],
		'type-space-after-colon': [2, 'always'],
		'subject-lowercase': [2, 'always'],
	},
	plugins: [
		{
			rules: {
				'type-space-after-colon': ({header}) => {

					let colonFirstIndex = header.indexOf(":");

					let offence = false;
					if ((colonFirstIndex > 0) && (header.length > colonFirstIndex)) {
						if (header[colonFirstIndex + 1] != ' ') {
							offence = true;
						}
					}

					return [
						!offence,
						`Please place a space after the first colon character in your commit message title`
					];
				},
				'subject-lowercase': ({subject}) => {

					let offence = false;
					if (subject != null && subject.length > 1) {
						offence = subject[0].toUpperCase() == subject[0]
							// to whitelist acronyms
							&& subject[1].toLowerCase() == subject[1];
					}

					return [
						!offence,
						`Please use lowercase as the first letter for your subject, i.e. the text after your area/scope`
					];
				}
			}
		}
	]
};

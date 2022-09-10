module.exports = {
	parserPreset: 'conventional-changelog-conventionalcommits',
	rules: {
		'body-leading-blank': [1, 'always'],
// disable this one until we find a way for URLs to be allowed:
//		'body-max-line-length': [2, 'always', 64],
		'footer-leading-blank': [1, 'always'],
		'footer-max-line-length': [2, 'always', 150],
		'header-max-length': [2, 'always', 50],
		'subject-case': [
			2,
			'never',
			['sentence-case', 'start-case', 'pascal-case', 'upper-case'],
		],
		'subject-full-stop': [2, 'never', '.'],
		'type-empty': [1, 'never'],
	}
};

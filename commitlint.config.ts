module.exports = {
    parserPreset: 'conventional-changelog-conventionalcommits',
    rules: {
        'body-leading-blank': [1, 'always'],
// disable this one until we find a way for URLs to be allowed:
//      'body-max-line-length': [2, 'always', 64],
        'footer-leading-blank': [1, 'always'],
        'footer-max-line-length': [2, 'always', 150],
        'header-max-length': [2, 'always', 50],
        'subject-full-stop': [2, 'never', '.'],
        'type-empty': [1, 'never'],
        'type-space-after-colon': [2, 'always'],
        'subject-lowercase': [2, 'always'],
    },
    plugins: [
        // TODO (ideas for more rules):
        // * Don't put space after comma in area/scope (type).
        // * Don't put space before parentheses or slash in area/scope.
        // * Better rule than body-max-line-length that ignores line if it starts with `[x] ` where x is a number.
        // * 'body-full-stop' which finds paragraphs in body without full-stop (which ignores lines in same way as suggested above).
        // * 'body-paragraph-uppercase' which finds paragraphs in body starting with lowercase.
        // * Detect if paragraphs in body have been cropped too shortly (less than 64 chars). -> maybe only a warning
        // * Detect trailing spaces.
        // * Detect reverts which have not been elaborated.
        // * Detect WIP commits without a number.
        // * Reject #XYZ refs in favour for full URLs.
        // * If full URL for commit found, reject in favour for just the commit hash.

        {
            rules: {
                'type-space-after-colon': ({header}: {header:any}) => {
                    // to convert from 'any' type
                    let headerStr = String(header);

                    let colonFirstIndex = headerStr.indexOf(":");

                    let offence = false;
                    if ((colonFirstIndex > 0) && (headerStr.length > colonFirstIndex)) {
                        if (headerStr[colonFirstIndex + 1] != ' ') {
                            offence = true;
                        }
                    }

                    return [
                        !offence,
                        `Please place a space after the first colon character in your commit message title`
                    ];
                },
                'subject-lowercase': ({subject}: {subject:any}) => {
                    // to convert from 'any' type
                    let subjectStr = String(subject);

                    let offence = false;
                    if (subjectStr != null && subjectStr.length > 1) {
                        offence = subjectStr[0].toUpperCase() == subjectStr[0]
                            // to whitelist acronyms
                            && subjectStr[1].toLowerCase() == subjectStr[1];
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

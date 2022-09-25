const { spawnSync } = require('child_process');

const ls = spawnSync('ls', ['-lh', '/usr']);
const unexistent = spawnSync('thiscommandshouldnotexist', ['--foo']);

test('spawnSync1', () => {
    expect(ls.error).toBe(undefined);
});
test('spawnSync2', () => {
    expect(unexistent.error).not.toBe(undefined);
});

let commitMsgWithNoSpace = 'foo:bar'
test('type-space-after-colon1', () => {
    let typeSpaceAfterColon1 = spawnSync('npx', ['commitlint', '--verbose'], { input: commitMsgWithNoSpace });

    expect(typeSpaceAfterColon1.status).not.toBe(0);
});

let commitMsgWithSpace = 'foo: bar'
test('type-space-after-colon2', () => {
    let typeSpaceAfterColon2 = spawnSync('npx', ['commitlint', '--verbose'], { input: commitMsgWithSpace });

    expect(typeSpaceAfterColon2.status).toBe(0);
});

let commitMsgWithNoSpaceBeforeColonButAtTheEnd = 'foo: a tale of bar:baz'
test('type-space-after-colon3', () => {
    let typeSpaceAfterColon3 = spawnSync('npx', ['commitlint', '--verbose'], { input: commitMsgWithNoSpaceBeforeColonButAtTheEnd });

    expect(typeSpaceAfterColon3.status).toBe(0);
});

let commitMsgWithUppercaseAfterColon = "foo: Bar baz"
test('subject-lowercase1', () => {
    let subjectLowerCase1 = spawnSync('npx', ['commitlint', '--verbose'], { input: commitMsgWithUppercaseAfterColon });

    expect(subjectLowerCase1.status).not.toBe(0);
});

let commitMsgWithLowercaseAfterColon = "foo: bar baz"
test('subject-lowercase2', () => {
    let subjectLowerCase2 = spawnSync('npx', ['commitlint', '--verbose'], { input: commitMsgWithLowercaseAfterColon });

    expect(subjectLowerCase2.status).toBe(0);
});

let commitMsgWithAcronymAfterColon = "foo: BAR baz"
test('subject-lowercase3', () => {
    let subjectLowerCase3 = spawnSync('npx', ['commitlint', '--verbose'], { input: commitMsgWithAcronymAfterColon });

    //console.log("=============>" + subjectLowerCase3.stdout);
    expect(subjectLowerCase3.status).toBe(0);
});

const { spawnSync } = require('child_process');

const ls = spawnSync('ls', ['-lh', '/usr']);
const unexistent = spawnSync('thiscommandshouldnotexist', ['--foo']);

test('spawnSync1', () => {
    expect(ls.error).toBe(undefined);
});
test('spawnSync2', () => {
    expect(unexistent.error).not.toBe(undefined);
});


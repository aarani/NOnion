using DotNetOnion.Cells;
using System;
using System.Collections.Generic;
using System.Text;

namespace DotNetOnion.Helpers
{
    public static class CommandsHelper
    {
        public static bool IsVariableLength(byte command) =>
            command == 7 || command >= 128;

        public static bool IsRelayCell(byte command) =>
            command == 9 || command == 3;

        //FIXME: Maybe reflection is cleaner?
        public static Cell GetCell(byte command)
        {
            return command switch
            {
                0 => new CellPadding(),
                3 => new CellRelayEncrypted(),
                4 => new CellDestroy(),
                5 => new CellCreateFast(),
                6 => new CellCreatedFast(),
                7 => new CellVersions(),
                8 => new CellNetInfo(),
                129 => new CellCerts(),
                130 => new CellAuthChallenge(),
                _ => throw new NotImplementedException(),
            };
        }
    }
}

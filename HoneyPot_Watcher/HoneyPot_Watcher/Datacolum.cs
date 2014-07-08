using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HoneyPot_Watcher
{
    class Datacolumn
    {
        public string Name;
        public System.Data.SqlDbType DataType;
        public short Length = -1;
        public object Value = null;
        public Datacolumn(string name, System.Data.SqlDbType type)
        {
            Name = name;
            DataType = type;
        }
        public Datacolumn(string name,System.Data.SqlDbType type,short length)
        {
            Name = name;
            DataType = type;
            Length = length;
        }
    }
        
}

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HoneyPot_Manager
{
    public partial class AddIP : Form
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="m"></param>
        /// <param name="type">type : 1. addIP 2. addProtected</param>
        public AddIP(Manager m,string type)
        {
            InitializeComponent();
            _manager = m;
            _type = type;
        }

        private Manager _manager;
        private string _type;
        
        private void button1_Click(object sender, EventArgs e)
        {
            if (textBox1.Text != "" && textBox2.Text != "" && textBox3.Text != "")
            {
                _manager.addIP(_type, textBox1.Text,textBox2.Text,textBox3.Text);
                this.Close();
            }
            else
            {
                MessageBox.Show("empty text;");
            }
        }
    }
}

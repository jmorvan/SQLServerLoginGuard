using System.ServiceProcess;
using System.Timers;

namespace SQLServerLoginGuard
{
    public partial class SQLServerLoginGuardService : ServiceBase
    {

        const int delay = 60000;
        const int eventLinesToRequest = 100;
        const int blacklistTreshold = 10;

        public SQLServerLoginGuardService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            var helper = new SQLServerLoginGuardHelper(delay,eventLinesToRequest,blacklistTreshold);
            Timer timer = new Timer();
            timer.Interval = delay;
            timer.Elapsed += new ElapsedEventHandler(helper.serviceWorker);
            timer.Start();
        }

        protected override void OnStop()
        {
        }


    }
}

import copy
import unittest
from device_cpu_grading import grade, delta


class CpuGradingTests(unittest.TestCase):
    def fixture(self):
        run='a'*32;lines=[];host=[];mid=0;index=0
        for iteration in range(8):
            for path in ('identity','test','large'):
                events=[]
                for _ in range(2 if path=='large' else 1):
                    mid+=1;events.append([2,0,0,48,mid])
                    for kind in (1,2,3):
                        wall=100+index*10
                        lines.append(f'COAPTIC_CPU run={run} i={index} k={kind} w={wall} c={wall-100} b=50 r=50 mid={mid} tok={mid:016x} n=48')
                        index+=1
                host.append(dict(case='complete_operation',passed=True,path=path,iteration=iteration,elapsed_ns=1000000,events=events))
        lines.append(f'COAPTIC_CPU_RESOURCE run={run} at=500 rx=16 tx=16 free=100 minimum=90 largest=80 stack_free=70')
        lines.append(f'COAPTIC_CPU_END run={run} count={index} overflow=false rows_bytes=28672')
        host.append(dict(passed=True,run_id=run,security='durable-oscore',case='timing_campaign',completed=24))
        return lines,host,run

    def test_complete_authenticated_cohort_and_consistent_scheduler_accounting(self):
        lines,host,run=self.fixture()
        result=grade(lines,host,run)
        self.assertEqual(len(result['operations']),24)
        self.assertEqual(result['operations'][0]['exchanges'][0]['receive_to_send']['task_cpu_us'],10)
        for change in ('overflow','foreign','accounting','missing','host-mid','resource','late-resource','extra-receive','inventory','summary','unprotected'):
            with self.subTest(change=change):
                changed=copy.deepcopy(lines);peer=copy.deepcopy(host)
                if change=='overflow': changed[-1]=changed[-1].replace('false','true')
                elif change=='foreign':changed[0]=changed[0].replace(run,'b'*32)
                elif change=='accounting':changed[1]=changed[1].replace('c=10','c=30')
                elif change=='missing':changed.pop(1)
                elif change=='host-mid':peer[0]['events'][0][4]=999
                elif change=='resource':changed.pop(-2)
                elif change=='late-resource':changed[-2]=changed[-2].replace('at=500','at=2000')
                elif change=='extra-receive':
                    changed.insert(-2,f'COAPTIC_CPU run={run} i=96 k=1 w=1060 c=960 b=50 r=50 mid=999 tok=0000000000000999 n=48')
                    changed[-1]=changed[-1].replace('count=96','count=97')
                elif change=='inventory':peer[0]['path']='test'
                elif change=='summary':peer[-1]['completed']=23
                elif change=='unprotected':peer[-1]['security']='unprotected'
                with self.assertRaises(ValueError):grade(changed,peer,run)

    def test_exact_cpu_blocked_ready_split(self):
        result=delta(dict(w=100,c=20,b=30,r=50),dict(w=130,c=25,b=40,r=65))
        self.assertEqual(result,dict(wall_us=30,task_cpu_us=5,blocked_us=10,ready_unscheduled_us=15))

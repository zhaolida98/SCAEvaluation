import csv
import os
import shutil
from generate_mvn_gt import generate_mvn_dep_tree_gt
from util.depUtils import generate_class_path, generate_dep_tree
from util.utils import pretty_log, exec_command

def batch_generate_mvn_gt(manifest_csv):
    csv_reader = csv.DictReader(manifest_csv)
    for row in csv_reader:
        scan_type = row['type']
        target_name = row['target']
        workding_dir = row['working_path']
        report_name = target_name
        if scan_type != 'source':
            continue

        report_path = os.path.join(workding_dir, scan_type+'_report')
        full_target_path = os.path.join(workding_dir, target_name)
        dep_tree_txt = f"{full_target_path}/dep.txt"
        build_classpath_txt =  f"{full_target_path}/classpath.txt"

        # write dependency:tree to dep.txt
        dep_ok = generate_dep_tree(full_target_path)

        # write dependency:class-path to classpath.txt
        cp_ok = generate_class_path(full_target_path)
        
        # calculate the ground truth by dep.txt and classpath.txt
        if dep_ok and cp_ok:
            generate_mvn_dep_tree_gt(dep_tree_txt, build_classpath_txt, report_path, report_name)
        
        # copy the groundturth component into saas report
        src_groundtruth_component_report = os.path.join(report_path, f"groundtruth-component-{report_name}.csv")
        dst_groundtruth_component_report = os.path.join(os.path.join(workding_dir, 'saas_report'), f"groundtruth-component-{report_name}.csv")
        assert os.path.isfile(src_groundtruth_component_report)
        shutil.copyfile(src_groundtruth_component_report, dst_groundtruth_component_report)

    manifest_csv.close()

if __name__ == '__main__':
    manifest_csv_path = f"/root/SCAEvaluation/testsuite2/manifest-testsuite2.csv"
    manifest_csv = open(manifest_csv_path, 'r')
    batch_generate_mvn_gt(manifest_csv)

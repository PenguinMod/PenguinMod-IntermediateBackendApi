class ReportList {
    constructor(reports) {
        if (!Array.isArray(reports)) {
            this.reports = [];
        }
        /**
         * @type {Array<object>}
         */
        this.reports = structuredClone(reports);
        this.reports.sort((a, b) => {
            if (a.reporter < b.reporter) { return -1; }
            if (a.reporter > b.reporter) { return 1; }
            return 0;
        });
    }
    toMerged() {
        const newReports = [];
        let currentReport = {
            valid: false,
            reporter: '',
            reason: ''
        };
        let counter = 1;
        for (const report of this.reports) {
            if (report.reporter !== currentReport.reporter) {
                // add to new reports
                if (currentReport.valid !== false) {
                    newReports.push(currentReport);
                }
                // set this as the new base report
                currentReport = report;
                currentReport.ids = [report.id];
                counter = 1;
                currentReport.reason = `(Report 1)\n${currentReport.reason}`;
                continue;
            }
            // merge this reports data with the current report
            counter++;
            currentReport.reason += `\n(Report ${counter})\n${report.reason}`;
            currentReport.ids.push(report.id);
        }
        // add final report
        if (currentReport.valid !== false) {
            newReports.push(currentReport);
        }
        return newReports;
    }
}

module.exports = ReportList;
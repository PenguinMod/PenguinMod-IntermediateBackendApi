class GenericList {
    constructor(items = [], paginated = true, extraDetails = {}) {
        this.items = items;
        this.paginated = paginated;
        this.extraDetails = extraDetails;

        this.pageLength = 12;
    }

    /**
     * Converts this list to JSON, with options allowed.
     * @param {boolean?} applyPagination Determines whether or not to only include the specified page.
     * @param {number?} page 0-indexed page on where to cut.
     * @param {number?} pageLength The length of each page. If not specified, this.pageLength will be used.
     * @returns {object} JSON Object
     */
    toJSON(applyPagination, page, pageLength) {
        const json = {
            items: this.items,
            paginated: this.paginated,
            listCount: this.items.length,
            attributes: this.extraDetails,
        };
        if (applyPagination) {
            json.page = Number(page);
            json.paginated = true;
            if (isNaN(json.page)) {
                json.page = 0;
            }
            // cut to page
            const length = pageLength ? pageLength : this.pageLength;
            const startIdx = json.page * length;
            const endIdx = (json.page + 1) * length;
            const items = json.items;
            json.items = items.slice(startIdx, endIdx);
        }
        return json;
    }
    /**
     * Converts this list to a JSON string, with options allowed.
     * Uses this.toJSON
     * @param {boolean?} applyPagination Determines whether or not to only include the specified page.
     * @param {number?} page 0-indexed page on where to cut.
     * @param {number?} pageLength The length of each page. If not specified, this.pageLength will be used.
     * @returns {string} JSON Object stringified
     */
    toString(...args) {
        const json = this.toJSON(...args);
        return JSON.stringify(json);
    }
}

module.exports = GenericList;
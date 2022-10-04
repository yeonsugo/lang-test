/**
 * Copyright (c) 2018 IoTcube, Inc.
 * All right reserved.
 *
 * This software is the confidential and proprietary information of IoTcube, Inc.
 * You shall not disclose such Confidential Information and
 * shall use it only in accordance with the terms of the license agreement
 * you entered into with IoTcube, Inc.
*/

package com.iotcube.analyzer.analysis.controller;

import java.io.IOException;
import java.util.*;

import javax.annotation.*;
import javax.servlet.http.*;

import com.iotcube.analyzer.analysis.util.LicenseAnalysisUtil;
import com.iotcube.analyzer.analysis.util.ScanResultUtil;
import com.iotcube.analyzer.common.service.AnalyzerConfig;
import com.iotcube.analyzer.iam.model.OrganizationBlackListWhiteListVo;
import com.iotcube.analyzer.iam.model.UserContext;
import com.iotcube.analyzer.iam.service.OrganizationService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

import org.quartz.SchedulerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.*;

import com.iotcube.analyzer.analysis.dao.UploadScanDao;
import com.iotcube.analyzer.analysis.model.*;
import com.iotcube.analyzer.analysis.model.ScanWhiteBoxVo.*;
import com.iotcube.analyzer.analysis.scheduler.JobSchedulerService;
import com.iotcube.analyzer.analysis.scheduler.JobVO;
import com.iotcube.analyzer.analysis.service.*;
import com.iotcube.analyzer.runtime.annotation.*;
import com.iotcube.analyzer.runtime.model.*;
import com.iotcube.analyzer.runtime.util.FileUtil;
import com.iotcube.analyzer.runtime.util.IdGenUtil;

import lombok.extern.slf4j.*;

/**
 *
 * @author hyeonggookim
 * @since 2019. 6. 26.
 */
@Slf4j
@Controller
@RequestMapping(value = Constants.API_URI_VERSION + "/orgs/{orgId}/workspaces/{wsId}/projects/{projId}/whitebox")
public class WhiteBoxController {

	@Resource(name = "com.iotcube.analyzer.analysis.service.WhiteBoxService")
	private WhiteBoxService whiteBoxService;

	@Resource(name = "com.iotcube.analyzer.iam.service.OrganizationService")
	private OrganizationService organizationService;

	@Resource(name = "com.iotcube.analyzer.common.service.AnalyzerConfig")
	private AnalyzerConfig analyzerConfig;

	@Resource(name = "com.iotcube.analyzer.analysis.dao.UploadScanDao")
	private UploadScanDao uploadScanDao;

	@Autowired
	private JobSchedulerService jobSchedulerService;

	@Resource(name = "com.iotcube.analyzer.runtime.util.FileUtil")
	private FileUtil fileUtil;

	/**
	 * jquery file upload에서 요청하는 메소드, 실제 업로드시는 POST로 던짐.
	 * 
	 * @return
	 */
	@NoAuthCheck
	@RequestMapping(method = RequestMethod.GET)
	@ApiOperation(value = "[UI에서 필요] jquery file upload에서 요청하는 메소드", notes = "이 API는 실제로 쓰이는 로직이 없지만 jquery file upload시 필요한 메소드라 추가되었다.\n")
	protected String upload() {
		return "";
	}

	/**
	 * WhiteBox 분석 수행
	 * 
	 * @param orgId
	 * @param wsId
	 * @param projId
	 * @param request
	 * @param response
	 * @return
	 */
	@WorkspaceAnalyzerCheck
	@RequestMapping(headers = ("content-type=multipart/*"), method = RequestMethod.POST)
	@ResponseBody
	@ApiOperation(value = "스캔 아웃풋 파일 분석", notes = "이 API는 LabScan의 scanOutput.zip 파일을 입력받아 분석을 수행한다.\n")
	protected ResponseObject<ScanWhiteBoxVo> analysisWhiteBox(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔아웃풋 파일 (.zip)", required = true) MultipartHttpServletRequest request,
			HttpServletResponse response,
			@ApiParam(value = "소스 트리구조 저장 여부 (Y/N) default:N", required = false, example = "N") @RequestParam(required = false, defaultValue = "N") String storeStructure) {

		ResponseObject<ScanWhiteBoxVo> responseObject = new ResponseObject<ScanWhiteBoxVo>();
		// 1. build an iterator
		Iterator<String> itr = request.getFileNames();
		MultipartFile mpf = null;

		ScanWhiteBoxVo result = null;
		// 2. get each file
		while (itr.hasNext()) {
			// 2.1 get next MultipartFile

			mpf = request.getFile(itr.next());
			log.debug(mpf.getOriginalFilename());
			String userId = UserContext.get().getUserId();
			String scanId = IdGenUtil.getNextId();
			String uploadId = IdGenUtil.getNextId();

			String destination = fileUtil.getDestinationPath(Constants.UPLOAD_SOURCE, orgId, wsId, projId, uploadId,
					"scanOutput");
			String fileFullPath = fileUtil.copyFileToPath(mpf, destination);

			JobVO.Info.Input input = new JobVO.Info.Input();

			Map<String, String> metaMap = new HashMap<String, String>();
			metaMap.put("orgId", orgId);
			metaMap.put("wsId", wsId);
			metaMap.put("projId", projId);
			metaMap.put("scanId", scanId);
			metaMap.put("uploadId", uploadId);
			metaMap.put("userId", userId);
			metaMap.put("storeStructure", storeStructure);
			metaMap.put("fileFullPath", fileFullPath);
			metaMap.put("originalFileName", mpf.getOriginalFilename());
			input.setMeta(metaMap);

			JobVO.Info info = new JobVO.Info();
			info.setGroup("LA");
			info.setInput(input);

			JobVO jobVO = new JobVO();
			jobVO.setInfo(info);

			try {
				jobSchedulerService.addToScanOutputQueue(jobVO);
			} catch (SchedulerException | IOException e) {
				e.printStackTrace();
				uploadScanDao.updateUploadScan(orgId, wsId, projId, scanId, Constants.STATUS_ANALYSIS_ERROR, null);
			}
		}

		responseObject.setData(result);

		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/summary", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "분석 요약정보 조회", notes = "이 API는 분석이 완료된 스캔의 요약정보를 조회한다.\n")
	protected ResponseObject<ScanWhiteBoxVo> selectScanSummary(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<ScanWhiteBoxVo> responseObject = new ResponseObject<ScanWhiteBoxVo>();

		responseObject.setData(whiteBoxService.selectScanSummary(orgId, wsId, projId, scanId));

		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/license", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "라이선스 결과 조회", notes = "이 API는 분석이 완료된 스캔의 라이선스 정보를 조회한다.\n")
	protected ResponseObject<List<AnalysisResultVo.LicenseResult>> selectScanLicenseResult(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<List<AnalysisResultVo.LicenseResult>> responseObject = new ResponseObject<List<AnalysisResultVo.LicenseResult>>();

		responseObject.setData(whiteBoxService.selectScanLicenseResult(orgId, wsId, projId, scanId));
		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/library", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "라이브러리 결과 조회", notes = "이 API는 분석이 완료된 스캔의 라이브러리 정보를 조회한다.\n")
	protected ResponseObject<ScanWhiteBoxVo> selectScanLibraryResult(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId,
			@ApiParam(value = "취약한 라이브러리 필터. true인 경우 취약한 라이브러리 목록만 리턴한다. (default는 false)", required = false, example = "false") @RequestParam(required = false, defaultValue = "false") String vulnOnly) {

		ResponseObject<ScanWhiteBoxVo> responseObject = new ResponseObject<ScanWhiteBoxVo>();
		ScanWhiteBoxVo scanWhiteBoxVo = whiteBoxService.selectScanLibraryResult(orgId, wsId, projId, scanId, vulnOnly);

		boolean bwComponentEnabled = analyzerConfig.isEnabled(Constants.TB_CONFIG_KEY_BLACKLIST_WHITELIST_COMPONENT);
		boolean bwCveEnabled = analyzerConfig.isEnabled(Constants.TB_CONFIG_KEY_BLACKLIST_WHITELIST_CVE);
		boolean bwLicenseEnabled = analyzerConfig.isEnabled(Constants.TB_CONFIG_KEY_BLACKLIST_WHITELIST_LICENSE);
		boolean licenseEnabled = analyzerConfig.isEnabled(Constants.TB_CONFIG_KEY_LICENSE);

		Map<String, OrganizationBlackListWhiteListVo> bwlist = new HashMap<String, OrganizationBlackListWhiteListVo>();
		Map<String, OrganizationBlackListWhiteListVo> bwLicenseList = new HashMap<String, OrganizationBlackListWhiteListVo>();
		Map<String, OrganizationBlackListWhiteListVo> bwCveList = new HashMap<String, OrganizationBlackListWhiteListVo>();

		if (bwComponentEnabled) {
			bwlist = ScanResultUtil
					.convertListToMap(organizationService.selectOrganizationBlackListWhiteList(orgId, "component"));
		}
		if (bwCveEnabled) {
			bwCveList = ScanResultUtil
					.convertListToMap(organizationService.selectOrganizationBlackListWhiteList(orgId, "cve"));
		}
		if (bwLicenseEnabled) {
			bwLicenseList = ScanResultUtil
					.convertListToMap(organizationService.selectOrganizationBlackListWhiteList(orgId, "license"));
		}

		responseObject.setData(scanWhiteBoxVo);

		List<LibraryResult> libraryResults = scanWhiteBoxVo.getLibraryResults();
		Map<String, String> map = new HashMap<>();

		if (null == libraryResults) {
			return responseObject;
		}

		for (int i = 0; i < libraryResults.size(); i++) {
			LibraryResult result = libraryResults.get(i);
			List<LibraryResult.Dependency> dependencies = result.getDependencies();

			if (null == dependencies) {
				continue;
			}

			for (int j = 0; j < dependencies.size(); j++) {
				String name = dependencies.get(j).getName();
				String bw = null;
				if (dependencies.get(j).getLanguage().equals("java")) {
					if (bwComponentEnabled) {
						bw = getBlackOrWhite(bwlist, dependencies.get(j).getProductKey());
					}
					if (null != bw) {
						dependencies.get(j).setBw(bw);
					}
				} else {
					if (bwComponentEnabled) {
						bw = getBlackOrWhite(bwlist, dependencies.get(j).getName());
					}
					if (null != bw) {
						dependencies.get(j).setBw(bw);
					}
				}

				List<Vulnerability> vulnerabilities = dependencies.get(j).getVulnerabilities();
				if (null != vulnerabilities) {
					for (Vulnerability v : vulnerabilities) {
						bw = null;
						if (bwCveEnabled) {
							bw = getBlackOrWhite(bwCveList, v.getRefId());
						}
						if (null != bw) {
							v.setBw(bw);
						}
					}
				}

				if (null != dependencies.get(j).getLicenses()) {
					Collections.sort(dependencies.get(j).getLicenses());
					if (bwLicenseEnabled) {
						applyBlackOrWhiteToLicenseList(bwLicenseList, dependencies.get(j).getLicenses());
					}
				}
				List<LicenseVO> licenses = whiteBoxService.selectLicenseInfo(dependencies.get(j).getProductKey(),
						dependencies.get(j).getLatestVersion(), dependencies.get(j).getLanguage(), true);
				for (LicenseVO l : licenses) {
					if (l.getVersion().toLowerCase().equals(dependencies.get(j).getLatestVersion().toLowerCase())) {
						List<License> licenseList = l.getStandardLicenses();
						if (null != licenseList) {
							Collections.sort(licenseList);
							if (bwLicenseEnabled) {
								applyBlackOrWhiteToLicenseList(bwLicenseList, licenseList);
							}
							VersionVo versionVo = new VersionVo();
							versionVo.setProductKey(dependencies.get(j).getProductKey());
							if (licenseEnabled) {
								versionVo.setLicenseIds(l.getLicenseIds());
								versionVo.setStandardLicenses(licenseList);
								versionVo.setLicenses(licenseList);
								versionVo.setVersion(dependencies.get(j).getVersion());
								LicenseAnalysisUtil.selectStandardLicense(whiteBoxService, versionVo);
								dependencies.get(j).setLatestVersionLicenses(versionVo.getStandardLicenses());
							}
						}
					}
				}
			}
		}
		// END merge

		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/source", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "소스 결과 조회", notes = "이 API는 분석이 완료된 스캔의 소스 정보를 조회한다.\n"
			+ "스캔아웃풋 파일 분석 API의 store structure가 Y였던 분석만 리턴가능하다.\n")
	protected ResponseObject<ScanWhiteBoxVo> selectSource(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<ScanWhiteBoxVo> responseObject = new ResponseObject<ScanWhiteBoxVo>();

		responseObject.setData(whiteBoxService.selectScanSource(orgId, wsId, projId, scanId));

		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/newscan", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "신규 분석 결과 조회", notes = "이 API는 LabScan이 분석을 시도했을 때 새로운 스캔이 등록되었는지 여부를 찾는 API이다.\n"
			+ "파라미터로 들어온 scanId 의 등록시간보다 더 나중에 등록된 스캔이 있으면 해당 스캔정보를 리턴한다.\n")
	protected ResponseObject<ScanWhiteBoxVo> selectNewScan(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<ScanWhiteBoxVo> responseObject = new ResponseObject<ScanWhiteBoxVo>();

		responseObject.setData(whiteBoxService.selectNewScan(orgId, wsId, projId, scanId));

		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/codeclone", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "함수 취약점 결과 조회", notes = "이 API는 분석이 완료된 스캔의 함수 취약점 결과를 조회한다.\n")
	protected ResponseObject<ScanWhiteBoxVo> selectScanCodeCloneResult(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<ScanWhiteBoxVo> responseObject = new ResponseObject<ScanWhiteBoxVo>();
		ScanWhiteBoxVo scanWhiteBoxVo = whiteBoxService.selectScanCodeCloneResult(orgId, wsId, projId, scanId);

		boolean bwCveEnabled = analyzerConfig.isEnabled(Constants.TB_CONFIG_KEY_BLACKLIST_WHITELIST_CVE);

		if (null != scanWhiteBoxVo) {
			List<ScanWhiteBoxVo.CodeCloneResult> codeCloneResults = scanWhiteBoxVo.getCodeCloneResults();
			Map<String, OrganizationBlackListWhiteListVo> bwlist = new HashMap<String, OrganizationBlackListWhiteListVo>();
			if (bwCveEnabled) {
				bwlist = ScanResultUtil
						.convertListToMap(organizationService.selectOrganizationBlackListWhiteList(orgId, "cve"));
			}
			for (ScanWhiteBoxVo.CodeCloneResult result : codeCloneResults) {
				String bw = null;
				if (bwCveEnabled) {
					bw = getBlackOrWhite(bwlist, result.getCveId());
				}
				if (null != bw) {
					result.setBw(bw);
				}
			}
		}

		responseObject.setData(scanWhiteBoxVo);

		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/codeclone/tree", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "함수취약점의 트리 결과 조회", notes = "이 API는 분석이 완료된 스캔의 함수 취약점 결과를 UI에서 트리형태로 표현할 수 있도록 데이터를 반환한다.\n")
	protected ResponseObject<VulTree> selectScanCodeCloneResultTree(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<VulTree> responseObject = new ResponseObject<VulTree>();

		ScanWhiteBoxVo result = whiteBoxService.selectScanCodeCloneResult(orgId, wsId, projId, scanId);

		VulTree trees = new VulTree();
		trees.setName("/");
		trees.setChildren(new ArrayList<VulTree>());

		if (result.getCodeCloneResults() != null && !result.getCodeCloneResults().isEmpty()) {
			for (CodeCloneResult code : result.getCodeCloneResults()) {
				log.debug("tree size : {}", trees.getChildren().size());

				List<VulTree> _tempTrees = trees.getChildren();
				String[] paths = code.getFile().split("/");
				log.debug("file : {}", code.getFile());
				for (String path : paths) {
					log.debug("path : {}", path);
					VulTree _tree = new VulTree();
					_tree.setName(path);
					log.debug("_tempTrees : {}", _tempTrees);
					if (_tempTrees.contains(_tree)) { // 포함되어 있으면 아래거 확인..
						for (VulTree _tempTree : _tempTrees) {
							if (_tempTree.equals(_tree)) {
								log.debug("getTempTrees : {}. {}", _tree.getName(), _tempTree.getChildren());
								_tempTrees = _tempTree.getChildren();

								break;
							}
						}
					} else {
						log.debug("add children : {}. {}", _tempTrees.size(), _tree);
						_tree.setChildren(new ArrayList<VulTree>());
						_tempTrees.add(_tree);
						_tempTrees = _tree.getChildren();
					}
				}
				VulTree function = new VulTree();
				function.setName(code.getName());
				if (_tempTrees.contains(function)) {
					for (VulTree _tempTree : _tempTrees) {
						if (_tempTree.equals(function)) {
							VulTree cve = new VulTree();
							cve.setName(code.getCveId());
							cve.setPatch(code.getPatch());
							_tempTree.getChildren().add(cve);
							break;
						}
					}
				} else {
					VulTree cve = new VulTree();
					cve.setName(code.getCveId());
					cve.setPatch(code.getPatch());
					List<VulTree> cves = new ArrayList<VulTree>();
					cves.add(cve);
					function.setChildren(cves);
					_tempTrees.add(function);
				}

			}
		}
		responseObject.setData(trees);

		return responseObject;
	}

	@ScanOwnerCheck
	@RequestMapping(value = "/{scanId}", method = RequestMethod.DELETE)
	@ResponseBody
	@ApiOperation(value = "스캔 결과 삭제", notes = "이 API는 분석이 완료된 스캔을 삭제한다.\n")
	protected ResponseObject<Boolean> deleteScan(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<Boolean> responseObject = new ResponseObject<Boolean>();

		whiteBoxService.deleteScan(orgId, wsId, projId, scanId);
		responseObject.setData(true);

		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/sca", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "OSS 컴포넌트 결과 조회", notes = "이 API는 분석이 완료된 OSS 컴포넌트 결과를 조회한다.\n")
	protected ResponseObject<OssVersions> selectScaScanList(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<OssVersions> responseObject = new ResponseObject<OssVersions>();

		responseObject.setData(whiteBoxService.selectScanOssComponentList(orgId, wsId, projId, scanId));
		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/proprietarycomponents", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "자체 컴포넌트 결과 조회", notes = "이 API는 분석이 완료된 자체 컴포넌트 결과를 조회한다.\n")
	protected ResponseObject<ScanWhiteBoxVo> selectProprietaryComponents(
			@ApiParam(value = "조직 ID", required = true, example = "160082456568420001") @PathVariable String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "160082479206020002") @PathVariable String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "160082479772320003") @PathVariable String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "160082485358920017") @PathVariable String scanId) {

		ResponseObject<ScanWhiteBoxVo> responseObject = new ResponseObject<ScanWhiteBoxVo>();

		responseObject.setData(whiteBoxService.selectProprietaryComponents(orgId, wsId, projId, scanId));

		return responseObject;
	}

	@RequestMapping(value = "/{scanId}/opensources", method = RequestMethod.GET)
	@ResponseBody
	@ApiOperation(value = "프로젝트의 오픈소스 사용 정보 요청", notes = "프로젝트의 오픈소스 사용 정보 요청")
	@ApiResponses({ @ApiResponse(code = 200, message = "Success", response = OpenSources.class),
	// @ApiResponse(code = 500, message = "Internal Server Error"),
	// @ApiResponse(code = 404, message = "Not Found")
	})
	protected ResponseObject<OpenSources> getOpensourceList(
			@ApiParam(value = "조직 ID", required = true, example = "156093074914690001") @PathVariable("orgId") final String orgId,
			@ApiParam(value = "워크스페이스 ID", required = true, example = "156144233002290000") @PathVariable("wsId") final String wsId,
			@ApiParam(value = "프로젝트 ID", required = true, example = "156144247272700001") @PathVariable("projId") final String projId,
			@ApiParam(value = "스캔 ID", required = true, example = "156168452126520000") @PathVariable("scanId") final String scanId) {

		OpenSources openSources = new OpenSources();
		Map<String, String> map = new HashMap<>();

		ScanWhiteBoxVo scanWhiteBoxVo = whiteBoxService.selectScanLibraryResult(orgId, wsId, projId, scanId, "false");
		List<LibraryResult> libraryResults = scanWhiteBoxVo.getLibraryResults();

		if (null == libraryResults) {
			ResponseObject<OpenSources> responseObject = new ResponseObject<OpenSources>();
			return responseObject;
		}

		for (int i = 0; i < libraryResults.size(); i++) {
			LibraryResult result = libraryResults.get(i);
			List<LibraryResult.Dependency> dependencies = result.getDependencies();

			if (null == dependencies) {
				continue;
			}

			for (int j = 0; j < dependencies.size(); j++) {
				OpenSourceVO openSourceVO = new OpenSourceVO();
				String name = dependencies.get(j).getName();
				List<License> licenseList = dependencies.get(j).getLicenses();
				String url = "";
				String licenseName = "";

				// check duplicated.
				if (false == map.containsKey(name)) {
					LicenseVO foundLicense = null;
					List<LicenseVO> licenses = whiteBoxService.selectLicenseInfo(dependencies.get(j).getProductKey(),
							dependencies.get(j).getVersion(), dependencies.get(j).getLanguage(), false);
					if (null != licenses) {
						for (LicenseVO l : licenses) {
							if ((null != l.getUrl() || null != l.getScm())) {
								foundLicense = l;
								// log.debug("found license: {}", l.toString());
							}
							if (dependencies.get(j).getVersion() != null
									&& l.getVersion().toLowerCase()
											.equals(dependencies.get(j).getVersion().toLowerCase())
									&& (null != l.getUrl() || null != l.getScm())) {
								break;
							}
						}
					}

					if (null != foundLicense) {
						url = foundLicense.getUrl();
						if (null == url) {
							url = foundLicense.getScm();
						}
						log.debug("license: {}", foundLicense.toString());
					}

					map.put(name, name);
					openSourceVO.setName(name);
					openSourceVO.setSourceUrl(url);
					if (null != licenseList) {
						Collections.sort(licenseList);
						openSourceVO.setLicenses(licenseList);
					}
					openSources.getOpensources().add(openSourceVO);
				}
			}
		}

		ResponseObject<OpenSources> responseObject = new ResponseObject<OpenSources>();
		responseObject.setData(openSources);
		return responseObject;
	}

	private String getBlackOrWhite(Map<String, OrganizationBlackListWhiteListVo> bwlist, String target) {
		if (bwlist == null) {
			return null;
		}
		OrganizationBlackListWhiteListVo bvo = bwlist.get(target);
		if (bvo != null) {
			return bvo.getBlackOrWhite();
		}
		return null;
	}

	private void applyBlackOrWhiteToLicenseList(Map<String, OrganizationBlackListWhiteListVo> bwlist,
			List<License> licenses) {
		for (License l : licenses) {
			String bw = getBlackOrWhite(bwlist, l.getName());
			if (null != bw) {
				l.setBw(bw);
			}
		}
	}

}

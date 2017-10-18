// Copyright (c) 2017 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clientv2_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/testutils"
	"github.com/projectcalico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("ClusterInformation tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	name := "default"
	spec1 := apiv2.ClusterInformationSpec{
		ClusterGUID:   "test-cluster-guid1",
		ClusterType:   "test-cluster-type1",
		CalicoVersion: "test-version1",
	}
	spec2 := apiv2.ClusterInformationSpec{
		ClusterGUID:   "test-cluster-guid2",
		ClusterType:   "test-cluster-type2",
		CalicoVersion: "test-version2",
	}

	DescribeTable("ClusterInformation e2e CRUD tests",
		func(name string, spec1, spec2 apiv2.ClusterInformationSpec) {
			c, err := clientv2.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the ClusterInformation before it is created")
			res, outError := c.ClusterInformation().Update(ctx, &apiv2.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1234"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("resource does not exist: ClusterInformation(" + name + ")"))

			By("Attempting to creating a new ClusterInformation with name/spec1 and a non-empty ResourceVersion")
			res, outError = c.ClusterInformation().Create(ctx, &apiv2.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(res).To(BeNil())
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Getting ClusterInformation (name) before it is created")
			res, outError = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource does not exist: ClusterInformation(" + name + ")"))

			By("Attempting to create a new ClusterInformation with a non-default name and spec1")
			res1, outError := c.ClusterInformation().Create(ctx, &apiv2.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: "not-default"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("Cannot create a Cluster Information resource with a name other than \"default\""))

			By("Creating a new ClusterInformation with name/spec1")
			res1, outError = c.ClusterInformation().Create(ctx, &apiv2.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res1, apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1)

			// Track the version of the original data for name.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same ClusterInformation with name but with spec2")
			res1, outError = c.ClusterInformation().Create(ctx, &apiv2.ClusterInformation{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: ClusterInformation(" + name + ")"))
			// Check return value is actually the previously stored value.
			testutils.ExpectResource(res1, apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1)
			Expect(res1.ResourceVersion).To(Equal(rv1_1))

			By("Getting ClusterInformation (name) and comparing the output against spec1")
			res, outError = c.ClusterInformation().Get(ctx, name, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res, apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1)
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Listing all the ClusterInformation, expecting a single result with name/spec1")
			outList, outError := c.ClusterInformation().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			testutils.ExpectResource(&outList.Items[0], apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1)

			By("Updating ClusterInformation name with spec2")
			res1.Spec = spec2
			res1, outError = c.ClusterInformation().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res1, apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec2)

			// Track the version of the updated name data.
			rv1_2 := res1.ResourceVersion

			By("Updating ClusterInformation name without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			res, outError = c.ClusterInformation().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))
			Expect(res).To(BeNil())

			By("Updating ClusterInformation name using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			res1, outError = c.ClusterInformation().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: ClusterInformation(" + name + ")"))
			Expect(res1.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Getting ClusterInformation (name) with the original resource version and comparing the output against spec1")
				res, outError = c.ClusterInformation().Get(ctx, name, options.GetOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				testutils.ExpectResource(res, apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1)
				Expect(res.ResourceVersion).To(Equal(rv1_1))
			}

			By("Getting ClusterInformation (name) with the updated resource version and comparing the output against spec2")
			res, outError = c.ClusterInformation().Get(ctx, name, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(res, apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec2)
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Listing ClusterInformation with the original resource version and checking for a single result with name/spec1")
				outList, outError = c.ClusterInformation().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
				Expect(outError).NotTo(HaveOccurred())
				Expect(outList.Items).To(HaveLen(1))
				testutils.ExpectResource(&outList.Items[0], apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec1)
			}

			By("Listing ClusterInformation with the latest resource version and checking for one result with name/spec2")
			outList, outError = c.ClusterInformation().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(1))
			testutils.ExpectResource(&outList.Items[0], apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec2)

			if config.Spec.DatastoreType != apiconfig.Kubernetes {
				By("Deleting ClusterInformation (name) with the old resource version")
				_, outError = c.ClusterInformation().Delete(ctx, name, options.DeleteOptions{ResourceVersion: rv1_1})
				Expect(outError).To(HaveOccurred())
				Expect(outError.Error()).To(Equal("update conflict: ClusterInformation(" + name + ")"))
			}

			By("Deleting ClusterInformation (name) with the new resource version")
			dres, outError := c.ClusterInformation().Delete(ctx, name, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			testutils.ExpectResource(dres, apiv2.KindClusterInformation, testutils.ExpectNoNamespace, name, spec2)

			By("Listing all ClusterInformation and expecting no items")
			outList, outError = c.ClusterInformation().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

		},

		// Test 1: Pass two fully populated ClusterInformationSpecs and expect the series of operations to succeed.
		Entry("Two fully populated ClusterInformationSpecs", name, spec1, spec2),
	)

	Describe("ClusterInformation watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				Skip("Watch not supported yet with Kubernetes Backend")
			}
			c, err := clientv2.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing ClusterInformation with the latest resource version and checking for one result with name/spec2")
			outList, outError := c.ClusterInformation().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a ClusterInformation name/spec1 and storing the response")
			outRes1, err := c.ClusterInformation().Create(
				ctx,
				&apiv2.ClusterInformation{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.ClusterInformation().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.TestResourceWatch(w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.ClusterInformation().Delete(ctx, name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(apiv2.KindClusterInformation, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})
			testWatcher1.Stop()

			By("Configuring a ClusterInformation name2/spec2 and storing the response")
			outRes2, err := c.ClusterInformation().Create(
				ctx,
				&apiv2.ClusterInformation{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.ClusterInformation().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.TestResourceWatch(w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.ClusterInformation().Update(
				ctx,
				&apiv2.ClusterInformation{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv2.KindClusterInformation, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Modified,
					Previous: outRes2,
					Object:   outRes3,
				},
			})
			testWatcher2.Stop()

			By("Starting a watcher from rev0 watching name - this should get all events for name")
			w, err = c.ClusterInformation().Watch(ctx, options.ListOptions{Name: name, ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2_1 := testutils.TestResourceWatch(w)
			defer testWatcher2_1.Stop()
			testWatcher2_1.ExpectEvents(apiv2.KindClusterInformation, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Modified,
					Previous: outRes2,
					Object:   outRes3,
				},
			})
			testWatcher2_1.Stop()

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.ClusterInformation().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.TestResourceWatch(w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(apiv2.KindClusterInformation, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			testWatcher3.ExpectEvents(apiv2.KindClusterInformation, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher3.Stop()
		})
	})
})